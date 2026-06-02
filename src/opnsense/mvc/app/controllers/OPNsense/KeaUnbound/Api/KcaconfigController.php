<?php

/*
 * Copyright (C) 2026 tkr
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\KeaUnbound\Api;

use OPNsense\Base\ApiControllerBase;

/**
 * Check Kea DHCP subnet DDNS configuration against the kea-unbound-ddns plugin.
 *
 * Each subnet is classified into one of four buckets:
 *   no_ddns       - ddns-send-updates is false/absent
 *   wrong_target  - DDNS on, but DHCP-DDNS sends to a different IP:port
 *   tsig_mismatch - Right IP:port, but TSIG presence/key-name differs
 *   ok            - Correctly points at our listener with consistent TSIG
 *
 * GET /api/keaunbound/kcaconfig/check
 */
class KcaconfigController extends ApiControllerBase
{
    private $config_file     = '/conf/config.xml';
    private $ddns_conf_file  = '/usr/local/etc/kea/kea-dhcp-ddns.conf';

    // ── Kea Control Agent endpoint ────────────────────────────────────────────

    private function getKeaEndpoint()
    {
        $host = '127.0.0.1';
        $port = 8000;
        if (file_exists($this->config_file)) {
            $xml = simplexml_load_file($this->config_file);
            if ($xml !== false) {
                $h = $xml->xpath('//OPNsense/Kea/ctrl_agent/general/http_host');
                if (!empty($h) && (string)$h[0] !== '') {
                    $host = (string)$h[0];
                }
                $p = $xml->xpath('//OPNsense/Kea/ctrl_agent/general/http_port');
                if (!empty($p) && (string)$p[0] !== '') {
                    $port = intval((string)$p[0]);
                }
            }
        }
        return [$host, $port];
    }

    private function keaQuery($service)
    {
        list($host, $port) = $this->getKeaEndpoint();
        $url = "http://{$host}:{$port}/";
        $ch  = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['command' => 'config-get', 'service' => [$service]]));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);

        $response   = curl_exec($ch);
        $http_code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_errno = curl_errno($ch);
        curl_close($ch);

        if ($curl_errno !== 0 || $http_code !== 200 || $response === false) {
            return null;
        }
        $data = json_decode($response, true);
        if ($data === null) {
            return null;
        }
        // Normalize the list-of-maps response to a single map.
        if (is_array($data) && isset($data[0]) && is_array($data[0])) {
            $data = $data[0];
        }
        // result != 0 means the service is offline or rejected the command.
        if (($data['result'] ?? 1) !== 0) {
            return null;
        }
        return $data['arguments'] ?? [];
    }

    // ── Our plugin settings ───────────────────────────────────────────────────

    private function getPluginSettings()
    {
        $settings = [
            'address'      => '127.0.0.1',
            'port'         => 53535,
            'tsig_enabled' => false,
            'tsig_key'     => '',
        ];
        if (!file_exists($this->config_file)) {
            return $settings;
        }
        $xml = simplexml_load_file($this->config_file);
        if ($xml === false) {
            return $settings;
        }
        $g = $xml->xpath('//OPNsense/KeaUnbound/general');
        if (empty($g)) {
            return $settings;
        }
        $g = $g[0];
        if (!empty($g->port)) {
            $settings['port'] = intval((string)$g->port);
        }
        if ((string)$g->enable_tsig === '1') {
            $settings['tsig_enabled'] = true;
            $settings['tsig_key']     = trim((string)($g->tsig_key_name ?? ''));
        }
        return $settings;
    }

    // ── DHCP-DDNS domain index ────────────────────────────────────────────────

    /**
     * Build a lookup map from domain name (normalised, no trailing dot) to its
     * full domain config, read directly from kea-dhcp-ddns.conf.
     *
     * Kea's Control Agent cannot forward commands to the d2 daemon unless d2
     * has a control-socket configured — which OPNsense does not generate.
     * Reading the config file directly is simpler and always works.
     *
     * Returns [map, d2_ok]: map is name→domain, d2_ok is true if the file
     * was readable and parseable (daemon is configured, even if not queryable).
     */
    private function buildDomainMap()
    {
        $map = [];
        if (!file_exists($this->ddns_conf_file)) {
            return [$map, false];
        }
        $raw = file_get_contents($this->ddns_conf_file);
        if ($raw === false) {
            return [$map, false];
        }
        $conf = json_decode($raw, true);
        if (!is_array($conf)) {
            return [$map, false];
        }
        $domains = $conf['DhcpDdns']['forward-ddns']['ddns-domains'] ?? [];
        foreach ($domains as $domain) {
            $name = rtrim($domain['name'] ?? '', '.');
            if ($name !== '') {
                $map[$name] = $domain;
            }
        }
        return [$map, true];
    }

    // ── Subnet classification ─────────────────────────────────────────────────

    /**
     * Classify a single subnet into one of four buckets.
     *
     * @param array  $subnet      Kea subnet map
     * @param string $global_sfx  Global ddns-qualifying-suffix from dhcp config
     * @param array  $domain_map  Domain name → domain config from DHCP-DDNS
     * @param array  $plugin      Plugin settings from getPluginSettings()
     * @param bool   $d2_ok       Whether the DHCP-DDNS daemon was reachable
     * @return array ['ddns_status' => ..., 'detail' => ..., 'target' => ...]
     */
    private function classifySubnet($subnet, $global_sfx, $domain_map, $plugin, $d2_ok)
    {
        $ddns_enabled = isset($subnet['ddns-send-updates']) && $subnet['ddns-send-updates'] === true;

        if (!$ddns_enabled) {
            return [
                'ddns_status' => 'no_ddns',
                'detail'      => 'ddns-send-updates is not enabled for this subnet',
                'target'      => null,
            ];
        }

        // Effective qualifying suffix: subnet > global > empty
        $sfx = rtrim(
            $subnet['ddns-qualifying-suffix'] ?? $global_sfx ?? '',
            '.'
        );

        if (!$d2_ok) {
            return [
                'ddns_status' => 'd2_offline',
                'detail'      => 'DDNS is enabled but the Kea DHCP-DDNS daemon is not running — enable it under Services → Kea DHCP → DDNS Agent',
                'target'      => null,
            ];
        }

        // Find the DHCP-DDNS domain that matches this subnet's qualifying suffix.
        $domain = $domain_map[$sfx] ?? null;
        if ($domain === null && $sfx !== '') {
            // Try parent zones as fallback (e.g. "a.b.c" might match "b.c")
            $parts = explode('.', $sfx);
            while (count($parts) > 1) {
                array_shift($parts);
                $try = implode('.', $parts);
                if (isset($domain_map[$try])) {
                    $domain = $domain_map[$try];
                    break;
                }
            }
        }

        if ($domain === null) {
            return [
                'ddns_status' => 'wrong_target',
                'detail'      => 'DDNS is enabled but no DHCP-DDNS forward domain matches qualifying suffix "' . $sfx . '"',
                'target'      => null,
            ];
        }

        // Find a DNS server entry that matches our listener.
        $servers = $domain['dns-servers'] ?? [];
        $our_addr = $plugin['address'];
        $our_port = $plugin['port'];
        $matched  = null;
        $targets  = [];

        foreach ($servers as $srv) {
            $saddr = $srv['ip-address'] ?? '';
            $sport = intval($srv['port'] ?? 53);
            $targets[] = "{$saddr}:{$sport}";
            if ($saddr === $our_addr && $sport === $our_port) {
                $matched = $srv;
            }
        }

        if ($matched === null) {
            $target_str = empty($targets) ? 'no DNS servers configured' : implode(', ', $targets);
            return [
                'ddns_status' => 'wrong_target',
                'detail'      => "DHCP-DDNS sends to {$target_str} — plugin listens on {$our_addr}:{$our_port}",
                'target'      => $target_str,
            ];
        }

        // TSIG check: compare whether both sides agree on using TSIG and the key name.
        $domain_key = trim($domain['key-name'] ?? '');
        $our_tsig   = $plugin['tsig_enabled'];
        $our_key    = $plugin['tsig_key'];

        if ($our_tsig && $domain_key === '') {
            return [
                'ddns_status' => 'tsig_mismatch',
                'detail'      => 'Plugin requires TSIG but DHCP-DDNS sends unsigned updates for this domain',
                'target'      => "{$our_addr}:{$our_port}",
            ];
        }
        if (!$our_tsig && $domain_key !== '') {
            return [
                'ddns_status' => 'tsig_mismatch',
                'detail'      => "DHCP-DDNS signs updates with key \"{$domain_key}\" but plugin has TSIG disabled",
                'target'      => "{$our_addr}:{$our_port}",
            ];
        }
        if ($our_tsig && $domain_key !== $our_key) {
            return [
                'ddns_status' => 'tsig_mismatch',
                'detail'      => "TSIG key name mismatch: DHCP-DDNS uses \"{$domain_key}\", plugin expects \"{$our_key}\"",
                'target'      => "{$our_addr}:{$our_port}",
            ];
        }

        return [
            'ddns_status' => 'ok',
            'detail'      => $our_tsig
                ? "Correctly configured (TSIG key \"{$our_key}\")"
                : 'Correctly configured (no TSIG)',
            'target'      => "{$our_addr}:{$our_port}",
        ];
    }

    // ── Subnet extraction ─────────────────────────────────────────────────────

    private function extractSubnets($dhcp_args, $daemon, $domain_map, $plugin, $d2_ok)
    {
        $key        = $daemon === 'dhcp4' ? 'Dhcp4' : 'Dhcp6';
        $subnet_key = $daemon === 'dhcp4' ? 'subnet4' : 'subnet6';
        $subnets    = [];

        if (!isset($dhcp_args[$key])) {
            return $subnets;
        }
        $dhcp_config = $dhcp_args[$key];
        $global_sfx  = $dhcp_config['ddns-qualifying-suffix'] ?? '';

        // Top-level subnets
        foreach ($dhcp_config[$subnet_key] ?? [] as $subnet) {
            $subnets[] = $this->buildSubnetEntry($subnet, $global_sfx, $domain_map, $plugin, $d2_ok);
        }
        // Shared-network subnets
        foreach ($dhcp_config['shared-networks'] ?? [] as $net) {
            $net_sfx = $net['ddns-qualifying-suffix'] ?? $global_sfx;
            foreach ($net[$subnet_key] ?? [] as $subnet) {
                // Shared-network suffix overrides global but subnet suffix takes priority
                $effective_sfx = $subnet['ddns-qualifying-suffix'] ?? $net_sfx;
                $subnets[] = $this->buildSubnetEntry(
                    array_merge($subnet, ['_effective_sfx' => $effective_sfx]),
                    $global_sfx,
                    $domain_map,
                    $plugin,
                    $d2_ok
                );
            }
        }
        return $subnets;
    }

    private function buildSubnetEntry($subnet, $global_sfx, $domain_map, $plugin, $d2_ok)
    {
        $classified = $this->classifySubnet($subnet, $global_sfx, $domain_map, $plugin, $d2_ok);
        return [
            'subnet'      => $subnet['subnet'] ?? 'unknown',
            'ddns_enabled'=> isset($subnet['ddns-send-updates']) && $subnet['ddns-send-updates'] === true,
            'ddns_status' => $classified['ddns_status'],
            'detail'      => $classified['detail'],
            'target'      => $classified['target'],
            'comment'     => $subnet['comment'] ?? null,
        ];
    }

    // ── Public action ─────────────────────────────────────────────────────────

    public function checkAction()
    {
        $plugin = $this->getPluginSettings();

        // Read DHCP-DDNS forward zone configuration directly from the config
        // file. Kea's Control Agent cannot talk to d2 unless d2 has a
        // control-socket configured — which OPNsense does not generate.
        // Reading the file is simpler and always works while the daemon is up.
        list($domain_map, $d2_ok) = $this->buildDomainMap();

        $result = [
            'status'         => 'ok',
            'kea_error'      => null,
            'our_listener'   => [
                'address'      => $plugin['address'],
                'port'         => $plugin['port'],
                'tsig_enabled' => $plugin['tsig_enabled'],
            ],
            'd2_reachable'   => $d2_ok,
            'ipv4_subnets'   => [],
            'ipv6_subnets'   => [],
        ];

        // IPv4
        $dhcp4 = $this->keaQuery('dhcp4');
        if ($dhcp4 === null) {
            $result['status']    = 'error';
            $result['kea_error'] = 'Unable to query Kea DHCPv4. Check that Kea Control Agent is running.';
        } else {
            $result['ipv4_subnets'] = $this->extractSubnets($dhcp4, 'dhcp4', $domain_map, $plugin, $d2_ok);
        }

        // IPv6 (offline is not an error)
        $dhcp6 = $this->keaQuery('dhcp6');
        if ($dhcp6 !== null) {
            $result['ipv6_subnets'] = $this->extractSubnets($dhcp6, 'dhcp6', $domain_map, $plugin, $d2_ok);
        }

        return $result;
    }
}
