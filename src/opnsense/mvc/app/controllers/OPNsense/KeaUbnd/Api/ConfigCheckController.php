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

namespace OPNsense\KeaUbnd\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Kea\KeaDhcpv4;
use OPNsense\Kea\KeaDhcpv6;
use OPNsense\Kea\KeaDdns;
use OPNsense\Unbound\Unbound as UnboundModel;

/**
 * Check Kea DHCP subnet DDNS configuration against the kea-ubnd-ddns plugin.
 *
 * Each subnet is classified into one of four buckets:
 *   no_ddns       - ddns-send-updates is false/absent
 *   wrong_target  - DDNS on, but DHCP-DDNS sends to a different IP:port
 *   tsig_mismatch - Right IP:port, but TSIG presence/key-name differs
 *   ok            - Correctly points at our listener with consistent TSIG
 *
 * GET /api/keaubnd/config_check/check
 */
class ConfigCheckController extends ApiControllerBase
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
            'address'        => '127.0.0.1',
            'port'           => 53535,
            'tsig_enabled'   => false,
            'tsig_key'       => '',
            'tsig_secret'    => '',
            'tsig_algorithm' => '',
            'enable_logwatch' => true,
            'synthesize_ptr'  => true,
        ];
        if (!file_exists($this->config_file)) {
            return $settings;
        }
        $xml = simplexml_load_file($this->config_file);
        if ($xml === false) {
            return $settings;
        }
        $g = $xml->xpath('//OPNsense/KeaUbnd/general');
        if (empty($g)) {
            return $settings;
        }
        $g = $g[0];
        if (!empty($g->port)) {
            $settings['port'] = intval((string)$g->port);
        }
        if ((string)$g->enable_tsig === '1') {
            $settings['tsig_enabled']   = true;
            $settings['tsig_key']       = trim((string)($g->tsig_key_name ?? ''));
            $settings['tsig_secret']    = trim((string)($g->tsig_key_secret ?? ''));
            $settings['tsig_algorithm'] = trim((string)($g->tsig_algorithm ?? ''));
        }
        // synthesize_ptr defaults to true (1) when missing.
        $settings['synthesize_ptr'] = (string)($g->synthesize_ptr ?? '1') !== '0';
        // enable_logwatch defaults to true (1) when missing.
        $settings['enable_logwatch'] = (string)($g->enable_logwatch ?? '1') === '1';
        return $settings;
    }

    // The OPNsense system domain (//system/domain), used as the last-resort
    // domain basis for filling an empty qualifying suffix. Returns '' when no
    // system domain is configured, so callers can decide to skip rather than guess.
    private function getSystemDomain()
    {
        if (!file_exists($this->config_file)) {
            return '';
        }
        $xml = simplexml_load_file($this->config_file);
        if ($xml === false) {
            return '';
        }
        $n = $xml->xpath('//system/domain');
        return empty($n) ? '' : trim((string)$n[0]);
    }

    /**
     * Index the config.xml subnet nodes for a service, keyed by CIDR. Config Check
     * status comes from live Kea (config-get), but the push needs the OPNsense
     * UUID and the stored DDNS fields, which live in config.xml only.
     * Returns map: cidr => [uuid, suffix, forward_zone, option15].
     */
    private function loadSubnetIndex($service)
    {
        $idx = [];
        if (!file_exists($this->config_file)) {
            return $idx;
        }
        $xml = simplexml_load_file($this->config_file);
        if ($xml === false) {
            return $idx;
        }
        $subnet_key = $service === 'dhcp4' ? 'subnet4' : 'subnet6';
        $nodes = $xml->xpath("//OPNsense/Kea/{$service}/subnets/{$subnet_key}");
        if (empty($nodes)) {
            return $idx;
        }
        foreach ($nodes as $node) {
            $cidr = trim((string)$node->subnet);
            if ($cidr === '') {
                continue;
            }
            $opt15 = '';
            if (isset($node->option_data) && isset($node->option_data->domain_name)) {
                $opt15 = trim((string)$node->option_data->domain_name);
            }
            $idx[$cidr] = [
                'uuid'         => (string)$node['uuid'],
                'suffix'       => trim((string)$node->ddns_qualifying_suffix),
                'forward_zone' => trim((string)$node->ddns_forward_zone),
                'option15'     => $opt15,
            ];
        }
        return $idx;
    }

    /**
     * Resolve the "domain basis" used to fill an EMPTY qualifying suffix and/or
     * forward zone, and report where it came from. Order: existing suffix →
     * existing forward zone (dot stripped) → subnet option 15 → system domain →
     * none. Returns [basis (bare, no trailing dot), source].
     */
    private function resolveDomainBasis($entry, $system_domain)
    {
        if (!empty($entry['suffix'])) {
            return [rtrim($entry['suffix'], '.'), 'existing-suffix'];
        }
        if (!empty($entry['forward_zone'])) {
            return [rtrim($entry['forward_zone'], '.'), 'existing-forward'];
        }
        if (!empty($entry['option15'])) {
            return [rtrim($entry['option15'], '.'), 'option15'];
        }
        if ($system_domain !== '') {
            return [rtrim($system_domain, '.'), 'system'];
        }
        return ['', 'none'];
    }

    // ── DHCP-DDNS domain index ────────────────────────────────────────────────

    /**
     * Build a lookup map from domain name (normalised, no trailing dot) to its
     * full domain config, read directly from kea-dhcp-ddns.conf. Also returns
     * the set of reverse zone names (normalised, no trailing dot).
     *
     * We read the file directly because OPNsense does not generate a
     * control-socket section in kea-dhcp-ddns.conf, so kea-dhcp-ddns exposes no
     * control channel to query. If a future OPNsense provisions one, this could
     * instead resolve a d2 connection (resolveKeaSocket('d2') -- the resolver is
     * already service-generic) and run:
     *   $d2 = $this->keaQuery('d2');  // would need 'd2' wired into keaQuery
     *   $domains = $d2['DhcpDdns']['forward-ddns']['ddns-domains'] ?? [];
     *
     * Returns [forward_map, reverse_zones, d2_ok]:
     *   forward_map   name→domain for forward-ddns zones
     *   reverse_zones array of normalised reverse zone names (no trailing dot)
     *   d2_ok         true if the file was readable and parseable
     */
    private function buildDomainMap()
    {
        $map    = [];
        $revset = [];
        if (!file_exists($this->ddns_conf_file)) {
            return [$map, $revset, false];
        }
        $raw = file_get_contents($this->ddns_conf_file);
        if ($raw === false) {
            return [$map, $revset, false];
        }
        $conf = json_decode($raw, true);
        if (!is_array($conf)) {
            return [$map, $revset, false];
        }
        $domains = $conf['DhcpDdns']['forward-ddns']['ddns-domains'] ?? [];
        foreach ($domains as $domain) {
            $name = rtrim($domain['name'] ?? '', '.');
            if ($name !== '') {
                $map[$name] = $domain;
            }
        }
        $rev_domains = $conf['DhcpDdns']['reverse-ddns']['ddns-domains'] ?? [];
        foreach ($rev_domains as $domain) {
            $name = rtrim($domain['name'] ?? '', '.');
            if ($name !== '') {
                $revset[] = $name;
            }
        }
        return [$map, $revset, true];
    }

    /**
     * Return the arpa (reverse-DNS) form of an IP address, for zone-coverage
     * checks. Supports both IPv4 (in-addr.arpa) and IPv6 (ip6.arpa).
     * Returns '' on failure.
     */
    private function ipArpa($ip)
    {
        if (strpos($ip, ':') === false) {
            // IPv4: reverse the octets and append .in-addr.arpa
            $parts = explode('.', $ip);
            if (count($parts) !== 4) {
                return '';
            }
            return implode('.', array_reverse($parts)) . '.in-addr.arpa';
        }
        // IPv6: expand to full 128 bits, then reverse nibble-by-nibble and
        // append .ip6.arpa
        $binary = @inet_pton($ip);
        if ($binary === false || strlen($binary) !== 16) {
            return '';
        }
        $hex      = bin2hex($binary);
        $nibbles  = str_split($hex);
        $reversed = array_reverse($nibbles);
        return implode('.', $reversed) . '.ip6.arpa';
    }

    /**
     * Return true if the network address of $cidr falls within any of the
     * given $reverseZones (arpa suffix match, same logic as the Python helper).
     */
    private function subnetCoveredByReverse($cidr, $reverseZones)
    {
        if (empty($reverseZones)) {
            return false;
        }
        $parts   = explode('/', $cidr);
        $netAddr = trim($parts[0] ?? '');
        if ($netAddr === '') {
            return false;
        }
        $arpa = $this->ipArpa($netAddr);
        if ($arpa === '') {
            return false;
        }
        foreach ($reverseZones as $zone) {
            $zone = rtrim($zone, '.');
            if ($arpa === $zone || str_ends_with($arpa, '.' . $zone)) {
                return true;
            }
        }
        return false;
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
            'detail'      => 'Correctly configured',
            'target'      => "{$our_addr}:{$our_port}",
        ];
    }

    // ── Subnet extraction ─────────────────────────────────────────────────────

    private function extractSubnets($dhcp_args, $daemon, $domain_map, $plugin, $d2_ok,
                                    $reverseZones = [], $synthesizePtr = true,
                                    $subnetIndex = [], $system_domain = '')
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
            $subnets[] = $this->buildSubnetEntry(
                $subnet, $global_sfx, $domain_map, $plugin, $d2_ok,
                $reverseZones, $synthesizePtr, $daemon, $subnetIndex, $system_domain
            );
        }
        // Shared-network subnets
        foreach ($dhcp_config['shared-networks'] ?? [] as $net) {
            $net_sfx  = $net['ddns-qualifying-suffix'] ?? $global_sfx;
            $net_name = $net['name'] ?? 'unnamed';
            foreach ($net[$subnet_key] ?? [] as $subnet) {
                // Shared-network suffix overrides global but subnet suffix takes priority
                $effective_sfx = $subnet['ddns-qualifying-suffix'] ?? $net_sfx;
                $entry = $this->buildSubnetEntry(
                    array_merge($subnet, ['_effective_sfx' => $effective_sfx]),
                    $global_sfx,
                    $domain_map,
                    $plugin,
                    $d2_ok,
                    $reverseZones,
                    $synthesizePtr,
                    $daemon,
                    $subnetIndex,
                    $system_domain
                );
                $entry['advisories'][] = [
                    'level'   => 'warning',
                    'message' => 'This subnet is inside shared network "' . $net_name . '". '
                               . 'Subnet-level static reservations sync correctly, but reservations '
                               . 'placed directly on the shared-network object are not supported and '
                               . 'will be silently missed. DDNS for subnets in shared networks is '
                               . 'not tested (OPNsense issue #9427).',
                ];
                $subnets[] = $entry;
            }
        }
        return $subnets;
    }

    private function buildSubnetEntry($subnet, $global_sfx, $domain_map, $plugin, $d2_ok,
                                      $reverseZones = [], $synthesizePtr = true,
                                      $service = 'dhcp4', $subnetIndex = [], $system_domain = '')
    {
        $classified = $this->classifySubnet($subnet, $global_sfx, $domain_map, $plugin, $d2_ok);
        $ddns_enabled = isset($subnet['ddns-send-updates']) && $subnet['ddns-send-updates'] === true;
        // Raw (unstripped) effective suffix for trailing-dot advisory.
        $raw_sfx = $subnet['ddns-qualifying-suffix'] ?? $subnet['_effective_sfx'] ?? $global_sfx ?? '';

        // Push metadata: match this live-Kea subnet back to its config.xml node
        // (by CIDR) to recover the OPNsense UUID and resolve the domain basis the
        // push would apply to an empty suffix/forward zone.
        $cidr  = $subnet['subnet'] ?? '';
        $cfg   = $subnetIndex[$cidr] ?? null;
        $uuid  = $cfg['uuid'] ?? '';
        $suffix_set = $cfg !== null && $cfg['suffix'] !== '';
        list($domain_basis, $domain_source) = $cfg !== null
            ? $this->resolveDomainBasis($cfg, $system_domain)
            : ['', 'none'];

        return [
            'subnet'        => $cidr !== '' ? $cidr : 'unknown',
            'service'       => $service,
            'opnsense_uuid' => $uuid,
            'suffix_set'    => $suffix_set,
            'domain_basis'  => $domain_basis,
            'domain_source' => $domain_source,
            'ddns_enabled'  => $ddns_enabled,
            'ddns_status'   => $classified['ddns_status'],
            'detail'        => $classified['detail'],
            'target'        => $classified['target'],
            'comment'       => $subnet['comment'] ?? null,
            'advisories'    => $this->ddnsAdvisories(
                $subnet, $ddns_enabled, $raw_sfx,
                $reverseZones, $synthesizePtr
            ),
        ];
    }

    /**
     * Recommend the DDNS override settings for this plugin's architecture and flag the
     * incoherent "override no update without override client update" combination.
     *
     * These three options are evaluated by Kea/D2 from the subnet flags (before the
     * plugin's listener is involved); behaviour validated 2026-06 on the dev rig.
     * Recommended posture for the Unbound-bridge setup (no external DDNS server):
     * override-client-update, override-no-update, and update-on-renew all ON.
     *
     * $reverseZones  list of normalised reverse zone names from kea-dhcp-ddns.conf
     * $synthesizePtr whether the plugin's "synthesize PTR records" setting is on
     *
     * @return array list of ['level' => 'warning'|'info', 'message' => string]
     */
    private function ddnsAdvisories($subnet, $ddns_enabled, $raw_sfx = '',
                                    $reverseZones = [], $synthesizePtr = true)
    {
        if (!$ddns_enabled) {
            return [];
        }
        $onu = ($subnet['ddns-override-no-update'] ?? false) === true;
        $ocu = ($subnet['ddns-override-client-update'] ?? false) === true;
        $uor = ($subnet['ddns-update-on-renew'] ?? false) === true;
        $out = [];

        // Trailing dot on qualifying-suffix causes Kea to treat every hostname as
        // already absolute, skipping suffix appending entirely. Single-label clients
        // get no DNS record. Confirmed by Phase 1 testing (2026-06-08).
        if ($raw_sfx !== '' && substr($raw_sfx, -1) === '.') {
            $out[] = [
                'level'   => 'warning',
                'message' => 'Qualifying suffix "' . htmlspecialchars($raw_sfx) . '" ends with a trailing dot — '
                           . 'Kea treats single-label hostnames as already absolute and skips appending the suffix. '
                           . 'DNS records will not be registered for single-label hostnames. Remove the trailing dot.',
            ];
        }

        // Incoherent: overrides the strong "no updates" opt-out (N) but honors the
        // weaker "I'll do my own A" opt-out (S=0). Combine warning + recommendation.
        if ($onu && !$ocu) {
            $out[] = [
                'level'   => 'warning',
                'message' => 'Incoherent: override-no-update is on but override-client-update is off. '
                           . 'Recommend enabling override-client-update to avoid this conflict.',
            ];
        } elseif (!$ocu) {
            // Only show the info recommendation if the warning was not triggered.
            $out[] = [
                'level'   => 'info',
                'message' => 'Recommend enabling override-client-update.',
            ];
        }

        if (!$onu) {
            $out[] = [
                'level'   => 'info',
                'message' => 'Recommend enabling override-no-update.',
            ];
        }

        if (!$uor) {
            $out[] = [
                'level'   => 'info',
                'message' => 'Recommend enabling update-on-renew.',
            ];
        }

        // Conflict resolution mode: the Kea default (check-with-dhcid) uses DHCID
        // records to prevent different clients overwriting each other's DNS entries,
        // but also blocks dual-stack clients (same device, different DHCPv4/DHCPv6
        // identifiers) from registering both A and AAAA records. Since this plugin
        // writes to Unbound (a resolver, not an authoritative server) and is the sole
        // writer, DHCID protection provides no benefit. no-check-without-dhcid avoids
        // the dual-stack blocking problem. (See OPNsense issue #10212.)
        $crm = $subnet['ddns-conflict-resolution-mode'] ?? 'check-with-dhcid';
        if ($crm !== 'no-check-without-dhcid') {
            $out[] = [
                'level'   => 'info',
                'message' => 'Recommend setting conflict resolution mode to no-check-without-dhcid'
                           . ' (currently: ' . $crm . ').',
            ];
        }

        // If option 15 (domain-name) differs from the qualifying suffix, clients that
        // construct their FQDN by combining their hostname with the option 15 domain
        // will send FQDNs that D2 cannot route. Only option 12 (bare hostname) clients
        // are unaffected — Kea qualifies those with the suffix internally.
        $sfx_clean = rtrim($raw_sfx, '.');
        if ($sfx_clean !== '') {
            $opt15 = null;
            foreach ($subnet['option-data'] ?? [] as $opt) {
                if (($opt['name'] ?? '') === 'domain-name' || ($opt['code'] ?? 0) === 15) {
                    $opt15 = rtrim($opt['data'] ?? '', '.');
                    break;
                }
            }
            if ($opt15 !== null && $opt15 !== $sfx_clean) {
                $out[] = [
                    'level'   => 'info',
                    'message' => 'option 15 domain-name "' . htmlspecialchars($opt15) . '" differs from '
                               . 'ddns-qualifying-suffix "' . htmlspecialchars($sfx_clean) . '". '
                               . 'Clients that construct their FQDN from option 15 and send it via option 81 '
                               . 'will send names D2 cannot route — those clients will not get DNS records. '
                               . 'Recommended fix: set option 15 to match the qualifying suffix '
                               . '("' . htmlspecialchars($sfx_clean) . '"). '
                               . 'If you also need clients to search a broader domain (e.g. the parent zone), '
                               . 'add option 119 (Domain Search List) with both domains. '
                               . 'Clients that send only option 12 (bare hostname) are unaffected — '
                               . 'Kea qualifies those with the suffix before sending to D2.',
                ];
            }
        }

        // Duplicate-PTR advisory: synthesis ON + D2 has a reverse zone covering
        // this subnet → both paths produce identical PTRs (harmless, but redundant).
        if ($synthesizePtr && $this->subnetCoveredByReverse($subnet['subnet'] ?? '', $reverseZones)) {
            $out[] = [
                'level'   => 'info',
                'message' => 'PTRs for this subnet are written by both the plugin (PTR synthesis) and '
                           . 'Kea DHCP-DDNS (reverse zone configured) — this is harmless, but redundant. '
                           . 'Disable <strong>Synthesize PTR records</strong> in plugin Settings '
                           . 'if Kea DHCP-DDNS manages all reverse DNS for this subnet.',
            ];
        }

        return $out;
    }

    /**
     * Check whether Kea DHCP logging is configured so the log watcher can
     * function. The watcher tails /var/log/kea/kea_YYYYMMDD.log, which is
     * populated from syslog (OPNsense default: output=syslog → syslog-ng routes
     * to /var/log/kea/) or from a direct /var/log/kea/ path. Severity must be
     * INFO or DEBUG so DHCP4_RELEASE / DHCP6_RELEASE events (logged at INFO)
     * are captured.
     *
     * Returns ['ok' => true|false|null, 'detail' => string]
     *   null  = Kea not reachable, cannot determine
     */
    private function checkKeaLogging($dhcp4_args, $dhcp6_args)
    {
        $acceptable = ['debug', 'info'];
        $configs = [];
        if (is_array($dhcp4_args) && isset($dhcp4_args['Dhcp4'])) {
            $configs[] = $dhcp4_args['Dhcp4'];
        }
        if (is_array($dhcp6_args) && isset($dhcp6_args['Dhcp6'])) {
            $configs[] = $dhcp6_args['Dhcp6'];
        }
        if (empty($configs)) {
            return ['ok' => null, 'detail' => 'Kea not reachable'];
        }

        $issues = [];
        $found  = false;
        foreach ($configs as $cfg) {
            foreach ($cfg['loggers'] ?? [] as $logger) {
                $name = $logger['name'] ?? '';
                // Only check DHCP service loggers; skip ctrl-agent etc.
                if ($name !== '*' && strpos($name, 'kea-dhcp') === false) {
                    continue;
                }
                $found    = true;
                $severity = strtolower($logger['severity'] ?? 'info');
                if (!in_array($severity, $acceptable, true)) {
                    $issues[] = $name . ' severity is ' . strtoupper($severity) . ' — need INFO or DEBUG';
                }
                // Output must be 'syslog' (OPNsense default, routed via syslog-ng)
                // or a direct path under /var/log/kea/.
                $output_ok = false;
                $raw_outputs = [];
                foreach ($logger['output-options'] ?? $logger['output_options'] ?? [] as $opt) {
                    $out = $opt['output'] ?? '';
                    $raw_outputs[] = $out;
                    if ($out === 'syslog' || str_starts_with($out, '/var/log/kea/')) {
                        $output_ok = true;
                    }
                }
                if (!$output_ok) {
                    $issues[] = $name . ' output is ' . (implode(', ', $raw_outputs) ?: 'none')
                              . ' — need syslog or /var/log/kea/';
                }
            }
        }

        if (!$found) {
            return ['ok' => null, 'detail' => 'no explicit DHCP logger configured'];
        }
        if (empty($issues)) {
            return ['ok' => true, 'detail' => 'severity INFO · syslog → /var/log/kea/'];
        }
        return ['ok' => false, 'detail' => implode('; ', $issues)];
    }

    private function isListenerRunning()
    {
        $response = trim((new Backend())->configdRun('keaubnd status'));
        return strpos($response, 'is running') !== false;
    }

    private function isLogwatcherRunning()
    {
        $response = trim((new Backend())->configdRun('keaubnd logwatcher_status'));
        return strpos($response, 'is running') !== false;
    }

    private function isUnboundRunning()
    {
        $pidfile = '/var/run/unbound.pid';
        if (!file_exists($pidfile)) {
            return false;
        }
        $pid = intval(trim(@file_get_contents($pidfile)));
        if ($pid <= 0) {
            return false;
        }
        exec('ps -p ' . $pid . ' -o pid= 2>/dev/null', $ignored, $rc);
        return $rc === 0;
    }

    // Whether Kea HA is enabled for a service (//OPNsense/Kea/<svc>/ha/enabled).
    private function isHaEnabled($service)
    {
        if (!file_exists($this->config_file)) {
            return false;
        }
        $xml = simplexml_load_file($this->config_file);
        if ($xml === false) {
            return false;
        }
        $n = $xml->xpath("//OPNsense/Kea/{$service}/ha/enabled");
        return !empty($n) && (string)$n[0] === '1';
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
            'enabled'       => $this->isServiceEnabled($service),
            'reachable'     => $reachable,
            'manual_config' => $this->isManualConfig($service),
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

    // ── Push recommended settings ─────────────────────────────────────────────

    /**
     * The recommended DDNS posture for the Unbound-bridge architecture, applied
     * to each targeted subnet's config.xml node. The suffix/forward-zone pair is
     * filled only when empty (handled in applyRecommendedToNode); everything here
     * is set unconditionally.
     */
    private function recommendedFlags()
    {
        return [
            'ddns_override_no_update'      => '1',
            'ddns_override_client_update'  => '1',
            'ddns_update_on_renew'         => '1',
            'ddns_conflict_resolution_mode' => 'no-check-without-dhcid',
        ];
    }

    /**
     * Apply the recommended DDNS settings to a single subnet model node.
     *
     * Sets dns-server/port + the recommended flags unconditionally. Fills
     * ddns_qualifying_suffix and ddns_forward_zone only when they are empty,
     * deriving both from one domain basis so they stay consistent. Never
     * overwrites an existing suffix or forward zone.
     *
     * @return array ['action' => 'changed'|'skipped', 'reason' => string]
     */
    private function applyRecommendedToNode($node, $plugin, $system_domain, $domain_override = '')
    {
        $suffix  = trim((string)$node->ddns_qualifying_suffix);
        $forward = trim((string)$node->ddns_forward_zone);
        $opt15   = '';
        if (isset($node->option_data) && isset($node->option_data->domain_name)) {
            $opt15 = trim((string)$node->option_data->domain_name);
        }

        // Resolve a domain basis only if we actually need to fill something.
        $need_fill = ($suffix === '' || $forward === '');
        $basis = '';
        if ($need_fill) {
            if ($domain_override !== '') {
                $basis = rtrim($domain_override, '.');
            } else {
                list($basis, $source) = $this->resolveDomainBasis(
                    ['suffix' => $suffix, 'forward_zone' => $forward, 'option15' => $opt15],
                    $system_domain
                );
                if ($source === 'none') {
                    return ['action' => 'skipped', 'reason' => 'no domain configured (no suffix, forward zone, option 15, or system domain)'];
                }
            }
        }

        // Point DDNS at our listener and enable it (non-empty dns-server = enabled).
        $node->ddns_dns_server = $plugin['address'];
        $node->ddns_dns_port   = (string)$plugin['port'];
        foreach ($this->recommendedFlags() as $field => $value) {
            $node->$field = $value;
        }

        // Fill domain fields only when empty; keep them matching.
        if ($suffix === '') {
            $node->ddns_qualifying_suffix = $basis;
        }
        if ($forward === '') {
            $node->ddns_forward_zone = $basis . '.';
        }

        // TSIG: mirror the plugin's key onto the subnet when TSIG is enabled.
        if ($plugin['tsig_enabled'] && $plugin['tsig_key'] !== '') {
            $node->ddns_domain_key_name      = $plugin['tsig_key'];
            $node->ddns_domain_key_secret    = $plugin['tsig_secret'];
            $node->ddns_domain_key_algorithm = $plugin['tsig_algorithm'];
        }

        return ['action' => 'changed', 'reason' => ''];
    }

    /**
     * POST /api/keaubnd/config_check/push_settings
     *
     * Write the recommended DDNS settings into config.xml (via the core Kea
     * models) for one subnet (scope=subnet) or every subnet (scope=all), then
     * regenerate Kea config and restart. Gated by the plugin ACL (api/keaubnd/*).
     */
    public function pushSettingsAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST request required'];
        }
        $body  = $this->request->getJsonRawBody(true) ?: [];
        $scope = $body['scope'] ?? '';

        // The kea_sync hook only writes kea-dhcp-ddns.conf when the DDNS Agent is
        // enabled, so a push is a no-op without it. Fail fast with guidance — the
        // Config Check page already shows "DDNS Agent Down" with enable steps.
        if (!(new KeaDdns())->isEnabled()) {
            return [
                'status'  => 'error',
                'message' => 'The Kea DDNS Agent is not enabled. Enable it under '
                           . 'Services → Kea DHCP → DDNS Agent, then push again.',
            ];
        }

        $plugin        = $this->getPluginSettings();
        $system_domain = $this->getSystemDomain();

        $changed               = [];
        $skipped               = [];
        $errors                = [];
        $manual_config_skipped = [];

        // (service => model) for the services we will touch this call.
        $models = [];
        if ($scope === 'subnet') {
            $service = $body['service'] ?? '';
            $uuid    = $body['uuid'] ?? '';
            if (!in_array($service, ['dhcp4', 'dhcp6'], true) || $uuid === '') {
                return ['status' => 'error', 'message' => 'scope=subnet requires a valid service and uuid'];
            }
            if ($this->isManualConfig($service)) {
                return ['status' => 'error', 'message' => "Kea {$service} is in manual configuration mode — edit the config file directly"];
            }
            $mdl  = $service === 'dhcp4' ? new KeaDhcpv4() : new KeaDhcpv6();
            $ref  = 'subnets.' . ($service === 'dhcp4' ? 'subnet4' : 'subnet6') . '.' . $uuid;
            $node = $mdl->getNodeByReference($ref);
            if ($node === null) {
                return ['status' => 'error', 'message' => 'subnet not found'];
            }
            $models[$service] = $mdl;
            $res  = $this->applyRecommendedToNode($node, $plugin, $system_domain, $body['domain'] ?? '');
            $cidr = (string)$node->subnet;
            if ($res['action'] === 'changed') {
                $changed[] = $cidr;
            } else {
                $skipped[] = ['subnet' => $cidr, 'reason' => $res['reason']];
            }
        } elseif ($scope === 'all') {
            foreach (['dhcp4' => 'subnet4', 'dhcp6' => 'subnet6'] as $service => $subnet_key) {
                if ($this->isManualConfig($service)) {
                    $manual_config_skipped[] = $service;
                    continue;
                }
                $mdl = $service === 'dhcp4' ? new KeaDhcpv4() : new KeaDhcpv6();
                $models[$service] = $mdl;
                foreach ($mdl->subnets->$subnet_key->iterateItems() as $node) {
                    $cidr = (string)$node->subnet;
                    $res  = $this->applyRecommendedToNode($node, $plugin, $system_domain);
                    if ($res['action'] === 'changed') {
                        $changed[] = $cidr;
                    } else {
                        $skipped[] = ['subnet' => $cidr, 'reason' => $res['reason']];
                    }
                }
            }
        } else {
            return ['status' => 'error', 'message' => 'scope must be "all" or "subnet"'];
        }

        if (empty($changed)) {
            // Nothing written — report skips without touching config or restarting.
            $has_result = !empty($skipped) || !empty($manual_config_skipped);
            return [
                'status'                => $has_result ? 'ok' : 'error',
                'changed'               => [],
                'skipped'               => $skipped,
                'manual_config_skipped' => $manual_config_skipped,
                'errors'                => $has_result ? [] : [['subnet' => '*', 'message' => 'no subnets matched']],
            ];
        }

        // Validate every touched model before persisting.
        foreach ($models as $service => $mdl) {
            $msgs = $mdl->performValidation();
            foreach ($msgs as $msg) {
                $errors[] = ['subnet' => $service, 'message' => $msg->getField() . ': ' . $msg->getMessage()];
            }
        }
        if (!empty($errors)) {
            return ['status' => 'error', 'changed' => [], 'skipped' => $skipped,
                    'manual_config_skipped' => $manual_config_skipped, 'errors' => $errors];
        }

        // Persist all touched subnet models.
        foreach ($models as $mdl) {
            $mdl->serializeToConfig();
        }
        Config::getInstance()->save();

        // Apply: the 'kea restart' configd action runs Kea's own reconfigure
        // (the kea_sync hook → regenerates kea-dhcp{4,6}.conf and
        // kea-dhcp-ddns.conf) and then reloads the daemons. We drive it via
        // configd from PHP rather than shelling pluginctl ourselves. (Calling
        // plugins_configure('kea_sync') directly does not dispatch from an MVC
        // controller context — verified on OPNsense 26.1.)
        (new Backend())->configdRun('kea restart');

        return [
            'status'                => 'ok',
            'changed'               => $changed,
            'skipped'               => $skipped,
            'manual_config_skipped' => $manual_config_skipped,
            'errors'                => [],
        ];
    }

    // ── Summary advisories ────────────────────────────────────────────────────

    /**
     * Return summary-level (whole-config) advisories for global reservations and
     * shared networks found in a Kea daemon config map. Each advisory has:
     *   ['level' => 'warning'|'notice', 'heading' => string, 'message' => string]
     */
    private function globalReservationAdvisories($dhcp_config)
    {
        $out = [];

        if (!empty($dhcp_config['reservations'] ?? [])) {
            $out[] = [
                'level'   => 'notice',
                'heading' => 'Global reservations configured',
                'message' => 'Kea has reservations at the global Dhcp4/Dhcp6 level. '
                           . 'ISC recommends against assigning IP addresses in global reservations — '
                           . 'they are designed for options and hostname assignment only. '
                           . 'The plugin static sync reads ip-address from global reservations; '
                           . 'entries without an IP are silently skipped. '
                           . 'This configuration path is not tested.',
            ];
        }

        $shared_nets = $dhcp_config['shared-networks'] ?? [];
        if (!empty($shared_nets)) {
            $count = count($shared_nets);
            $names = implode(', ', array_map(
                function ($n) { return '"' . ($n['name'] ?? 'unnamed') . '"'; },
                $shared_nets
            ));
            $out[] = [
                'level'   => 'warning',
                'heading' => 'Shared networks detected',
                'message' => $count . ' shared network' . ($count !== 1 ? 's' : '') . ' detected: '
                           . $names . '. '
                           . 'Subnet-level static reservations within shared networks sync correctly, '
                           . 'but reservations placed directly on a shared-network object are not '
                           . 'supported and will be silently missed. '
                           . 'DDNS for subnets inside shared networks is not tested. '
                           . 'OPNsense GUI does not expose shared-network configuration '
                           . '(opnsense/core issue #9427) — if you are using shared networks via '
                           . 'manual config, verify DNS registration independently.',
            ];
        }

        return $out;
    }

    /**
     * Return a summary advisory if Kea HA is enabled for any service, read
     * directly from config.xml — no daemon probing needed.
     */
    private function haAdvisories()
    {
        $services = [];
        foreach (['dhcp4', 'dhcp6'] as $svc) {
            if ($this->isHaEnabled($svc)) {
                $services[] = $svc;
            }
        }
        if (empty($services)) {
            return [];
        }
        $label = implode(' and ', array_map('strtoupper', $services));
        return [[
            'level'   => 'warning',
            'heading' => 'Kea High Availability enabled',
            'message' => "Enabled for {$label}. Behavior with Kea HA is not tested or supported.",
        ]];
    }

    // ── Unbound DNS checks ────────────────────────────────────────────────────

    /**
     * Read Unbound settings from the model and return a list of check results.
     * Each item: ['id', 'level' (warning|notice), 'heading', 'message', 'fixable'].
     */
    private function getUnboundChecks()
    {
        $checks = [];
        try {
            $unbound = new UnboundModel();
        } catch (\Exception $e) {
            return $checks;
        }

        if ((string)$unbound->general->regdhcpstatic === '1') {
            $checks[] = [
                'id'      => 'regdhcpstatic',
                'level'   => 'warning',
                'heading' => 'Register DHCP Static Mappings is enabled',
                'message' => 'Unbound\'s built-in "Register DHCP Static Mappings" is also on. '
                           . 'Names registered there are owned by Unbound — this plugin skips them '
                           . 'rather than writing duplicates, so those hostnames are managed by '
                           . 'Unbound, not here. Disable it to let this plugin own all Kea '
                           . 'static reservation DNS entries.',
                'fixable' => true,
            ];
        }

        if ((string)$unbound->general->noarecords === '1') {
            $checks[] = [
                'id'      => 'noarecords',
                'level'   => 'warning',
                'heading' => 'AAAA-only mode is enabled',
                'message' => 'Unbound is configured to strip all A records from every response. '
                           . 'IPv4 DHCP hostnames registered by this plugin will be written to '
                           . 'Unbound\'s local store but will never be returned to clients.',
                'fixable' => false,
            ];
        }

        if ((string)$unbound->general->local_zone_type === 'redirect') {
            $checks[] = [
                'id'      => 'local_zone_type',
                'level'   => 'warning',
                'heading' => 'Local Zone Type is set to "redirect"',
                'message' => 'Redirect mode makes Unbound return a single address for every name '
                           . 'in the local zone. Per-name records registered by this plugin are '
                           . 'written correctly but will be shadowed by the redirect and never '
                           . 'returned to clients.',
                'fixable' => false,
            ];
        }

        if ((string)$unbound->forwarding->enabled === '1') {
            $checks[] = [
                'id'      => 'forwarding',
                'level'   => 'notice',
                'heading' => 'Query Forwarding is enabled',
                'message' => 'Names registered by this plugin are served directly from Unbound\'s '
                           . 'local store, unaffected by forwarding. Names not yet registered '
                           . '(e.g. a lease not yet synced) will be forwarded to the upstream '
                           . 'resolver rather than returning NXDOMAIN.',
                'fixable' => false,
            ];
        }

        return $checks;
    }

    /**
     * POST /api/keaubnd/config_check/disable_regdhcpstatic
     *
     * Turn off Unbound's "Register DHCP Static Mappings" and restart Unbound.
     */
    public function disableRegdhcpstaticAction()
    {
        if (!$this->request->isPost()) {
            return ['status' => 'error', 'message' => 'POST required'];
        }
        try {
            $unbound = new UnboundModel();
        } catch (\Exception $e) {
            return ['status' => 'error', 'message' => 'Could not load Unbound model: ' . $e->getMessage()];
        }
        $unbound->general->regdhcpstatic = '0';
        $msgs = $unbound->performValidation();
        foreach ($msgs as $msg) {
            return ['status' => 'error', 'message' => $msg->getField() . ': ' . $msg->getMessage()];
        }
        $unbound->serializeToConfig();
        Config::getInstance()->save();
        (new Backend())->configdRun('unbound restart');
        return ['status' => 'ok'];
    }

    // ── Public action ─────────────────────────────────────────────────────────

    public function checkAction()
    {
        $plugin = $this->getPluginSettings();

        // Read DHCP-DDNS forward zone configuration directly from the config
        // file. Kea's Control Agent cannot talk to d2 unless d2 has a
        // control-socket configured — which OPNsense does not generate.
        // Reading the file is simpler and always works while the daemon is up.
        list($domain_map, $reverse_zones, $d2_ok) = $this->buildDomainMap();

        $synthesize_ptr = $plugin['synthesize_ptr'];

        // config.xml-derived push metadata: UUID + stored DDNS fields per subnet.
        $system_domain = $this->getSystemDomain();
        $idx4 = $this->loadSubnetIndex('dhcp4');
        $idx6 = $this->loadSubnetIndex('dhcp6');

        $result = [
            'status'            => 'ok',
            'kea_error'         => null,
            'our_listener'       => [
                'address'            => $plugin['address'],
                'port'               => $plugin['port'],
                'tsig_enabled'       => $plugin['tsig_enabled'],
                'running'            => $this->isListenerRunning(),
                'logwatcher_enabled' => $plugin['enable_logwatch'],
                'logwatcher_running' => $this->isLogwatcherRunning(),
            ],
            'd2_reachable'      => $d2_ok,
            'ipv4_subnets'      => [],
            'ipv6_subnets'      => [],
            'summary_advisories' => [],
            'unbound_checks'    => $this->getUnboundChecks(),
            'unbound_running'   => $this->isUnboundRunning(),
        ];

        // HA advisory: config.xml-based, displayed in the Plugin Daemons section.
        $result['ha_advisories'] = $this->haAdvisories();
        $result['summary_advisories'] = [];

        // IPv4
        $dhcp4 = $this->keaQuery('dhcp4');
        if ($dhcp4 === null) {
            $result['status']    = 'error';
            $result['kea_error'] = 'Unable to query Kea DHCPv4. Check that the Kea DHCPv4 service is running.';
        } else {
            $result['ipv4_subnets'] = $this->extractSubnets(
                $dhcp4, 'dhcp4', $domain_map, $plugin, $d2_ok,
                $reverse_zones, $synthesize_ptr, $idx4, $system_domain
            );
            $result['summary_advisories'] = array_merge(
                $result['summary_advisories'],
                $this->globalReservationAdvisories($dhcp4['Dhcp4'] ?? [])
            );
        }

        // IPv6 (offline is not an error)
        $dhcp6 = $this->keaQuery('dhcp6');
        if ($dhcp6 !== null) {
            $result['ipv6_subnets'] = $this->extractSubnets(
                $dhcp6, 'dhcp6', $domain_map, $plugin, $d2_ok,
                $reverse_zones, $synthesize_ptr, $idx6, $system_domain
            );
            $result['summary_advisories'] = array_merge(
                $result['summary_advisories'],
                $this->globalReservationAdvisories($dhcp6['Dhcp6'] ?? [])
            );
        }

        // How the plugin is reaching each Kea daemon (for the Config Check page).
        $result['kea_control'] = [
            'dhcp4' => $this->describeConnection('dhcp4', $dhcp4 !== null),
            'dhcp6' => $this->describeConnection('dhcp6', $dhcp6 !== null),
        ];

        // Logging check: needs both DHCP query results, so runs after both queries.
        $result['our_listener']['logwatcher_logging'] = $this->checkKeaLogging($dhcp4, $dhcp6);

        return $result;
    }
}
