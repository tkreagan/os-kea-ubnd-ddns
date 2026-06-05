<?php

/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (C) 2026 Thomas Reagan
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
use OPNsense\Core\Backend;

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

    // Per-service generated Kea config files and their top-level keys, used to
    // discover each daemon's control socket (the Kea Control Agent is gone).
    private $conf_files = [
        'dhcp4' => '/usr/local/etc/kea/kea-dhcp4.conf',
        'dhcp6' => '/usr/local/etc/kea/kea-dhcp6.conf',
    ];
    private $root_keys = [
        'dhcp4' => 'Dhcp4',
        'dhcp6' => 'Dhcp6',
    ];
    // Hardcoded OPNsense defaults, matching what OPNsense core's KeaCtrl uses.
    private $default_sockets = [
        'dhcp4' => '/var/run/kea/kea4-ctrl-socket',
        'dhcp6' => '/var/run/kea/kea6-ctrl-socket',
    ];

    // ── Kea daemon control channel ────────────────────────────────────────────

    /**
     * Resolve how to reach a Kea daemon by reading configuration (never by
     * probing a running firewall). Mirrors the Python transport resolver:
     *   1. parse the active Kea conf file's control-socket(s) stanza
     *   2. else fall back to the hardcoded OPNsense default socket -- unless
     *      manual configuration is enabled, in which case we do not guess.
     * Returns ['type'=>'unix','path'=>..] or
     *         ['type'=>'http','host'=>..,'port'=>..,'tls'=>..,'verify'=>..],
     * or null if nothing usable could be resolved.
     */
    private function resolveKeaSocket($service)
    {
        $desc = $this->parseConfSocket($service);
        if ($desc !== null) {
            return $desc;
        }
        if ($this->isManualConfig($service)) {
            // Admin-owned config and no socket found -- do not guess a default.
            return null;
        }
        if (isset($this->default_sockets[$service])) {
            return ['type' => 'unix', 'path' => $this->default_sockets[$service]];
        }
        return null;
    }

    private function parseConfSocket($service)
    {
        $path     = $this->conf_files[$service] ?? null;
        $root_key = $this->root_keys[$service] ?? null;
        if ($path === null || $root_key === null || !file_exists($path)) {
            return null;
        }
        $raw = file_get_contents($path);
        if ($raw === false) {
            return null;
        }
        $conf = json_decode($raw, true);
        if (!is_array($conf) || !isset($conf[$root_key])) {
            return null;
        }
        $root = $conf[$root_key];
        if (isset($root['control-sockets']) && is_array($root['control-sockets'])) {
            $sockets = $root['control-sockets'];
        } elseif (isset($root['control-socket']) && is_array($root['control-socket'])) {
            $sockets = [$root['control-socket']];
        } else {
            return null;
        }
        return $this->selectSocket($sockets);
    }

    // Prefer an http(s) listener over a unix socket when both are present.
    private function selectSocket($sockets)
    {
        $unix = null;
        foreach ($sockets as $s) {
            $stype = strtolower($s['socket-type'] ?? '');
            if ($stype === 'http' || $stype === 'https') {
                $desc = $this->descFromSocket($s);
                if ($desc !== null) {
                    return $desc;
                }
            } elseif ($stype === 'unix' && $unix === null) {
                $unix = $s;
            }
        }
        return $unix !== null ? $this->descFromSocket($unix) : null;
    }

    private function descFromSocket($s)
    {
        $stype = strtolower($s['socket-type'] ?? '');
        if ($stype === 'unix') {
            $name = $s['socket-name'] ?? '';
            return $name !== '' ? ['type' => 'unix', 'path' => $name] : null;
        }
        if ($stype === 'http' || $stype === 'https') {
            $port = intval($s['socket-port'] ?? 0);
            if ($port === 0) {
                return null;
            }
            return [
                'type'   => 'http',
                'host'   => $s['socket-address'] ?? '127.0.0.1',
                'port'   => $port,
                'tls'    => $stype === 'https',
                'verify' => false,
            ];
        }
        return null;
    }

    private function isManualConfig($service)
    {
        if (!file_exists($this->config_file)) {
            return false;
        }
        $xml = simplexml_load_file($this->config_file);
        if ($xml === false) {
            return false;
        }
        // Confirmed on OPNsense 26.1: //OPNsense/Kea/dhcp{4,6}/general/manual_config.
        // Read defensively so a missing path simply means "not manual".
        $n = $xml->xpath("//OPNsense/Kea/{$service}/general/manual_config");
        if (empty($n)) {
            return false;
        }
        return in_array(strtolower(trim((string)$n[0])), ['1', 'true', 'yes'], true);
    }

    /**
     * Run config-get against a Kea daemon over whichever channel resolveKeaSocket
     * selected, normalize the response, and return its arguments map (or null if
     * the daemon is unreachable / offline / rejected the command).
     */
    private function keaQuery($service)
    {
        $desc = $this->resolveKeaSocket($service);
        if ($desc === null) {
            return null;
        }
        // No "service" routing field -- we talk directly to the daemon.
        $payload  = json_encode(['command' => 'config-get']);
        $response = $desc['type'] === 'unix'
            ? $this->keaQueryUnix($desc['path'], $payload)
            : $this->keaQueryHttp($desc, $payload);
        if ($response === null) {
            return null;
        }
        $data = json_decode($response, true);
        if ($data === null) {
            return null;
        }
        // Normalize the list-of-maps response (HTTP wraps in a one-element
        // array; unix returns a plain object) to a single map.
        if (is_array($data) && isset($data[0]) && is_array($data[0])) {
            $data = $data[0];
        }
        // result != 0 means the service is offline or rejected the command.
        if (($data['result'] ?? 1) !== 0) {
            return null;
        }
        return $data['arguments'] ?? [];
    }

    private function keaQueryUnix($path, $payload)
    {
        if (!file_exists($path)) {
            return null;
        }
        $sock = @stream_socket_client("unix://{$path}", $errno, $errstr, 5);
        if ($sock === false) {
            return null;
        }
        stream_set_timeout($sock, 5);
        // Kea reads until it has a complete JSON object, then responds and closes
        // the connection, so we write once and read until EOF.
        fwrite($sock, $payload . "\n");
        $response = '';
        while (!feof($sock)) {
            $chunk = fread($sock, 65536);
            if ($chunk === false) {
                break;
            }
            $response .= $chunk;
            $info = stream_get_meta_data($sock);
            if (!empty($info['timed_out'])) {
                fclose($sock);
                return null;
            }
        }
        fclose($sock);
        return $response !== '' ? $response : null;
    }

    private function keaQueryHttp($desc, $payload)
    {
        $scheme = !empty($desc['tls']) ? 'https' : 'http';
        $url = "{$scheme}://{$desc['host']}:{$desc['port']}/";
        $ch  = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        if (!empty($desc['tls']) && empty($desc['verify'])) {
            // OPNsense-generated certs are self-signed; skip verification.
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
        }
        $response   = curl_exec($ch);
        $http_code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_errno = curl_errno($ch);
        curl_close($ch);
        if ($curl_errno !== 0 || $http_code !== 200 || $response === false) {
            return null;
        }
        return $response;
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
     * We read the file directly because OPNsense does not generate a
     * control-socket section in kea-dhcp-ddns.conf, so kea-dhcp-ddns exposes no
     * control channel to query. If a future OPNsense provisions one, this could
     * instead resolve a d2 connection (resolveKeaSocket('d2') -- the resolver is
     * already service-generic) and run:
     *   $d2 = $this->keaQuery('d2');  // would need 'd2' wired into keaQuery
     *   $domains = $d2['DhcpDdns']['forward-ddns']['ddns-domains'] ?? [];
     *
     * Returns [map, d2_ok]: map is name→domain, d2_ok is true if the file
     * was readable and parseable.
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

        // Kea D2 requires the zone name to be an absolute FQDN ending with '.'.
        // Without the trailing dot, every update is dropped with
        // DHCP_DDNS_NO_FWD_MATCH_ERROR even though the domain name looks correct.
        $raw_name = $domain['name'] ?? '';
        if ($raw_name !== '' && substr($raw_name, -1) !== '.') {
            return [
                'ddns_status' => 'wrong_target',
                'detail'      => "DHCP-DDNS forward zone \"{$raw_name}\" is missing a required trailing dot — "
                               . "change it to \"{$raw_name}.\" in Services → Kea DHCP → DDNS.",
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

    private function isListenerRunning()
    {
        $response = trim((new Backend())->configdRun('keaunbound status'));
        return strpos($response, 'is running') !== false;
    }

    // Whether a Kea daemon is enabled in OPNsense (//OPNsense/Kea/<svc>/general/enabled).
    private function isServiceEnabled($service)
    {
        if (!file_exists($this->config_file)) {
            return false;
        }
        $xml = simplexml_load_file($this->config_file);
        if ($xml === false) {
            return false;
        }
        $n = $xml->xpath("//OPNsense/Kea/{$service}/general/enabled");
        return !empty($n) && (string)$n[0] === '1';
    }

    /**
     * Describe the control channel resolved for a daemon, for display on the
     * Config Check page. `$reachable` is whether config-get actually succeeded.
     * `enabled` lets the UI skip the reachability dot for daemons that are not
     * supposed to be running (e.g. DHCPv6 off), so a disabled service is not
     * shown as a problem.
     */
    private function describeConnection($service, $reachable)
    {
        $base = [
            'enabled'   => $this->isServiceEnabled($service),
            'reachable' => $reachable,
        ];
        $desc = $this->resolveKeaSocket($service);
        if ($desc === null) {
            return $base + ['method' => 'none', 'detail' => null];
        }
        if ($desc['type'] === 'unix') {
            return $base + ['method' => 'unix', 'detail' => $desc['path']];
        }
        $scheme = !empty($desc['tls']) ? 'https' : 'http';
        return $base + ['method' => 'http', 'detail' => "{$scheme}://{$desc['host']}:{$desc['port']}"];
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
                'running'      => $this->isListenerRunning(),
            ],
            'd2_reachable'   => $d2_ok,
            'ipv4_subnets'   => [],
            'ipv6_subnets'   => [],
        ];

        // IPv4
        $dhcp4 = $this->keaQuery('dhcp4');
        if ($dhcp4 === null) {
            $result['status']    = 'error';
            $result['kea_error'] = 'Unable to query Kea DHCPv4. Check that the Kea DHCPv4 service is running.';
        } else {
            $result['ipv4_subnets'] = $this->extractSubnets($dhcp4, 'dhcp4', $domain_map, $plugin, $d2_ok);
        }

        // IPv6 (offline is not an error)
        $dhcp6 = $this->keaQuery('dhcp6');
        if ($dhcp6 !== null) {
            $result['ipv6_subnets'] = $this->extractSubnets($dhcp6, 'dhcp6', $domain_map, $plugin, $d2_ok);
        }

        // How the plugin is reaching each Kea daemon (for the Config Check page).
        $result['kea_control'] = [
            'dhcp4' => $this->describeConnection('dhcp4', $dhcp4 !== null),
            'dhcp6' => $this->describeConnection('dhcp6', $dhcp6 !== null),
        ];

        return $result;
    }
}
