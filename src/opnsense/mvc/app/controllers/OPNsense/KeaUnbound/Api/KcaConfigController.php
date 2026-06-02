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

class KcaConfigController extends ApiControllerBase
{
    /**
     * Check Kea DHCP subnet configuration for DDNS settings.
     * Queries Kea control agent to see which subnets are configured for DDNS.
     *
     * GET /api/keaunbound/kca-config/check
     *
     * Returns JSON with structure:
     * {
     *   "status": "ok" | "error",
     *   "kea_error": null | "error message",
     *   "ipv4_subnets": [
     *     {
     *       "subnet": "10.0.0.0/24",
     *       "ddns_enabled": true | false,
     *       "status": "configured" | "not-configured"
     *     }
     *   ],
     *   "ipv6_subnets": [...]
     * }
     */
    public function checkAction()
    {
        $result = [
            'status' => 'ok',
            'kea_error' => null,
            'ipv4_subnets' => [],
            'ipv6_subnets' => []
        ];

        // Try to query Kea control agent for DHCPv4 config
        $ipv4_subnets = $this->queryKeaSubnets('dhcp4');
        if ($ipv4_subnets === null) {
            $result['status'] = 'error';
            $result['kea_error'] = 'Unable to query Kea DHCP. Check that Kea Control Agent is running and accessible at 127.0.0.1:8000';
        } else {
            $result['ipv4_subnets'] = $ipv4_subnets;
        }

        // Try to query Kea control agent for DHCPv6 config
        $ipv6_subnets = $this->queryKeaSubnets('dhcp6');
        if ($ipv6_subnets === null) {
            // DHCPv6 might not be configured, that's okay
            if ($result['status'] !== 'error') {
                $result['ipv6_subnets'] = [];
            }
        } else {
            $result['ipv6_subnets'] = $ipv6_subnets;
        }

        return $result;
    }

    /**
     * Query Kea control agent for subnet configuration.
     *
     * @param string $daemon 'dhcp4' or 'dhcp6'
     * @return array|null Array of subnets with DDNS config, or null on error
     */
    private function queryKeaSubnets($daemon)
    {
        // Read the Kea Control Agent endpoint from the real core model
        // (//OPNsense/Kea/ctrl_agent/general/{http_host,http_port}).
        $config_file = '/conf/config.xml';
        $kea_host = '127.0.0.1';
        $kea_port = 8000;

        if (file_exists($config_file)) {
            $xml = simplexml_load_file($config_file);
            if ($xml !== false) {
                $host_node = $xml->xpath('//OPNsense/Kea/ctrl_agent/general/http_host');
                if (!empty($host_node) && (string)$host_node[0] !== '') {
                    $kea_host = (string)$host_node[0];
                }
                $port_node = $xml->xpath('//OPNsense/Kea/ctrl_agent/general/http_port');
                if (!empty($port_node) && (string)$port_node[0] !== '') {
                    $kea_port = intval((string)$port_node[0]);
                }
            }
        }

        // Query Kea control agent
        $url = "http://{$kea_host}:{$kea_port}/";
        // config-get returns the running daemon config under arguments.Dhcp4/Dhcp6
        // (there is no '{daemon}-get-config' command on Kea).
        $command = [
            'command' => 'config-get',
            'service' => [$daemon]
        ];

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'POST');
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($command));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
        ]);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);

        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_errno = curl_errno($ch);
        curl_close($ch);

        if ($curl_errno !== 0 || $http_code !== 200) {
            return null;
        }

        $data = json_decode($response, true);
        if ($data === null) {
            return null;
        }

        // The Control Agent returns a list of per-service response maps;
        // normalize to the single relevant map.
        if (is_array($data) && isset($data[0]) && is_array($data[0])) {
            $data = $data[0];
        }

        // Parse response
        $subnets = [];

        // Response structure: {"result": 0, "text": "...", "arguments": {"Dhcp4": {...}}}
        if (isset($data['arguments'])) {
            $key = $daemon === 'dhcp4' ? 'Dhcp4' : 'Dhcp6';
            if (isset($data['arguments'][$key])) {
                $dhcp_config = $data['arguments'][$key];

                // Extract subnets
                $subnet_key = $daemon === 'dhcp4' ? 'subnet4' : 'subnet6';
                if (isset($dhcp_config[$subnet_key]) && is_array($dhcp_config[$subnet_key])) {
                    foreach ($dhcp_config[$subnet_key] as $subnet) {
                        $ddns_enabled = isset($subnet['ddns-send-updates']) && $subnet['ddns-send-updates'] === true;

                        $subnets[] = [
                            'subnet' => $subnet['subnet'] ?? 'unknown',
                            'ddns_enabled' => $ddns_enabled,
                            'status' => $ddns_enabled ? 'configured' : 'not-configured',
                            'comment' => $subnet['comment'] ?? null
                        ];
                    }
                }
            }
        }

        return $subnets;
    }
}
