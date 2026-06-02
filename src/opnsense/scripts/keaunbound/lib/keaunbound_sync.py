#!/usr/local/bin/python3
"""
keaunbound_sync.py -- Shared library for Kea-Unbound sync utilities.

Provides:
  - Kea control agent API queries (reservations, leases)
  - Unbound control wrapper
  - host_entries.conf parser
  - Record parsing and cross-reference logic
  - Error handling for missing/unavailable services
  - Syslog logging
"""

import ipaddress
import json
import logging
import logging.handlers
import re
import requests
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

# Constants
CONFIG_XML = "/conf/config.xml"
HOST_ENTRIES = "/var/unbound/host_entries.conf"
UNBOUND_CONTROL = "/usr/local/sbin/unbound-control"
SYSLOG_IDENT = "kea-unbound-sync"

# Custom exception for Kea unavailable
class KeaUnavailableError(Exception):
    """Raised when kea-ctrl-agent is not available or not responding."""
    pass

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Set up syslog logging with optional stderr for debugging."""
    logger = logging.getLogger(SYSLOG_IDENT)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Syslog handler
    handler = logging.handlers.SysLogHandler(
        address="/var/run/log",
        facility=logging.handlers.SysLogHandler.LOG_DAEMON
    )
    formatter = logging.Formatter(f"{SYSLOG_IDENT}: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Stderr handler for verbose mode
    if verbose:
        stderr = logging.StreamHandler(sys.stderr)
        stderr.setFormatter(formatter)
        logger.addHandler(stderr)

    return logger

def get_kea_ctrl_config() -> Tuple[str, int]:
    """
    Read kea-ctrl-agent config from OPNsense config.xml.
    Returns (host, port). Defaults to 127.0.0.1:8000.
    Raises KeaUnavailableError if kea-ctrl-agent is not enabled.
    """
    try:
        tree = ET.parse(CONFIG_XML)
        root = tree.getroot()
        node = root.find("OPNsense/Kea/KeaCtrlAgent/general")

        if node is None:
            raise KeaUnavailableError("Kea control agent config not found in config.xml")

        enabled = node.find("enabled")
        if enabled is None or enabled.text != "1":
            raise KeaUnavailableError("Kea control agent is not enabled")

        # Read host and port with defaults
        host_node = node.find("server_ip")
        host = host_node.text.strip() if host_node is not None and host_node.text else "127.0.0.1"

        port_node = node.find("server_port")
        port = int(port_node.text.strip()) if port_node is not None and port_node.text else 8000

        return host, port
    except ET.ParseError as e:
        raise KeaUnavailableError(f"Cannot parse config.xml: {e}")
    except Exception as e:
        raise KeaUnavailableError(f"Error reading kea-ctrl-agent config: {e}")

def query_kea_api(command: str, arguments: Optional[Dict] = None,
                  service: str = "dhcp4", timeout: float = 5.0) -> Dict:
    """
    Query kea-ctrl-agent REST API.
    Returns the response dict from Kea.
    Raises KeaUnavailableError if ctrl-agent is unavailable/unresponsive.
    """
    try:
        host, port = get_kea_ctrl_config()
        url = f"http://{host}:{port}/"

        payload = {"command": command, "service": [service]}
        if arguments:
            payload["arguments"] = arguments

        resp = requests.post(url, json=payload, timeout=timeout)
        resp.raise_for_status()

        data = resp.json()
        if data.get("result") != 0:
            raise KeaUnavailableError(f"Kea command '{command}' failed: {data.get('text', 'unknown error')}")

        return data
    except requests.exceptions.ConnectionError as e:
        raise KeaUnavailableError(f"Kea control agent connection refused: {e}")
    except requests.exceptions.Timeout:
        raise KeaUnavailableError(f"Kea control agent timeout after {timeout}s")
    except requests.exceptions.RequestException as e:
        raise KeaUnavailableError(f"Kea control agent request failed: {e}")

def query_kea_reservations(service: str = "dhcp4") -> List[Dict]:
    """
    Query all static reservations from Kea.
    Returns list of reservation dicts with keys: hostname, ip, ipv6
    Raises KeaUnavailableError if Kea is unavailable.
    """
    try:
        resp = query_kea_api("reservation-get-all", service=service)
        reservations = []

        for reservation in resp.get("arguments", {}).get("reservations", []):
            res_dict = {
                "hostname": reservation.get("hostname", ""),
                "ip": None,
                "ipv6": None,
            }

            # Extract IPv4
            if service == "dhcp4":
                res_dict["ip"] = reservation.get("ipv4-address")

            # Extract IPv6
            if service == "dhcp6":
                res_dict["ipv6"] = reservation.get("ipv6-address")

            if res_dict["hostname"] and (res_dict["ip"] or res_dict["ipv6"]):
                reservations.append(res_dict)

        return reservations
    except KeaUnavailableError:
        raise

def query_kea_leases(service: str = "dhcp4") -> List[Dict]:
    """
    Query all active leases from Kea.
    Returns list of lease dicts with keys: hostname, ip, ipv6, expires
    Raises KeaUnavailableError if Kea is unavailable.
    """
    try:
        resp = query_kea_api("lease-get-all", service=service)
        leases = []

        for lease in resp.get("arguments", {}).get("leases", []):
            # Only include leases with valid expiration (not expired)
            expires = lease.get("expire", 0)
            if expires == 0 or expires == -1:  # 0 or -1 means infinite/never expires
                expires = 86400  # Default to 1 day for infinite leases

            lease_dict = {
                "hostname": lease.get("hostname", ""),
                "ip": None,
                "ipv6": None,
                "expires": expires,
            }

            if service == "dhcp4":
                lease_dict["ip"] = lease.get("ip-address")

            if service == "dhcp6":
                lease_dict["ipv6"] = lease.get("ip-address")

            if lease_dict["hostname"] and (lease_dict["ip"] or lease_dict["ipv6"]):
                leases.append(lease_dict)

        return leases
    except KeaUnavailableError:
        raise

def read_host_entries() -> Dict[str, List[str]]:
    """
    Parse host_entries.conf and return dict of {name: [entries]}.
    Each entry is a raw line from the config (local-data or local-data-ptr).
    Returns empty dict if file doesn't exist.
    """
    entries = {}

    try:
        with open(HOST_ENTRIES) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Extract the name from local-data or local-data-ptr
                if line.startswith("local-data:"):
                    # Format: local-data: "name TTL IN TYPE rdata"
                    match = re.search(r'local-data:\s+"([^"\s]+)', line)
                    if match:
                        name = match.group(1).rstrip(".")
                        if name not in entries:
                            entries[name] = []
                        entries[name].append(line)

                elif line.startswith("local-data-ptr:"):
                    # Format: local-data-ptr: "ip rdata"
                    # For PTR, the "name" is the IP address
                    match = re.search(r'local-data-ptr:\s+"([^\s"]+)', line)
                    if match:
                        ip = match.group(1)
                        if ip not in entries:
                            entries[ip] = []
                        entries[ip].append(line)
    except FileNotFoundError:
        pass
    except Exception as e:
        logging.getLogger(SYSLOG_IDENT).warning(f"Error reading {HOST_ENTRIES}: {e}")

    return entries

def reverse_ptr(ip: str) -> Optional[str]:
    """
    Return the PTR name for an IP address.
    Works for both IPv4 (in-addr.arpa) and IPv6 (ip6.arpa).
    Returns None if IP is invalid.
    """
    try:
        return str(ipaddress.ip_address(ip).reverse_pointer)
    except ValueError:
        return None

def unbound_control(args: List[str], timeout: float = 10.0) -> bool:
    """
    Call unbound-control with given arguments.
    Returns True on success, False on failure.
    """
    cmd = [UNBOUND_CONTROL] + args
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.getLogger(SYSLOG_IDENT).error(f"unbound-control timeout: {' '.join(args)}")
        return False
    except Exception as e:
        logging.getLogger(SYSLOG_IDENT).error(f"unbound-control failed: {e}")
        return False

def unbound_list_local_data() -> Dict[str, List[str]]:
    """
    Query Unbound's local_data store via list_local_data.
    Returns dict of {name: [entries]} for all A/AAAA/PTR records.
    """
    local_data = {}

    try:
        result = subprocess.run(
            [UNBOUND_CONTROL, "list_local_data"],
            capture_output=True, text=True, timeout=10.0
        )
        if result.returncode != 0:
            return local_data

        # Format: "name. TTL IN TYPE rdata"
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue

            name = parts[0].rstrip(".")
            rdtype = parts[3]

            # Only track A, AAAA, PTR
            if rdtype in ("A", "AAAA", "PTR"):
                if name not in local_data:
                    local_data[name] = []
                local_data[name].append(line)

    except Exception as e:
        logging.getLogger(SYSLOG_IDENT).warning(f"Failed to query list_local_data: {e}")

    return local_data

def is_in_host_entries(name: str, host_entries: Dict[str, List[str]]) -> bool:
    """Check if name appears in host_entries.conf."""
    return name in host_entries
