#!/usr/bin/env python3
"""DHCPv4 DDNS test harness for Kea subnet ddns-* override testing.

Crafts DISCOVER/REQUEST with precise Client-FQDN (option 81) flag control,
captures OFFER/ACK, and reports the assigned IP + the server's returned FQDN
flags (S/O/N). Supports a RENEWING-state request for update-on-renew tests.

Run as root (raw sockets):  sudo python3 ddns_test.py --help
"""
import argparse, json, random, sys
from scapy.all import (Ether, IP, UDP, BOOTP, DHCP, sendp, srp1, conf, get_if_hwaddr)

# RFC 4702 Client-FQDN flag bits
F_S = 0x01  # server does forward (A) update
F_O = 0x02  # override (server-set in reply)
F_E = 0x04  # canonical wire-format encoding
F_N = 0x08  # no DNS updates


def mac_str_to_bytes(mac):
    return bytes(int(b, 16) for b in mac.split(":"))


def wire_name(fqdn):
    """Encode a fully-qualified name in canonical (wire) format with root."""
    out = b""
    for label in fqdn.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def opt81(flags, fqdn):
    return ("client_FQDN", bytes([flags, 0, 0]) + wire_name(fqdn))


def parse_fqdn_flags(pkt):
    """Return (flags_int, hostname_str) from a reply's option 81, or (None, None)."""
    if not pkt or not pkt.haslayer(DHCP):
        return None, None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] in ("client_FQDN", 81):
            val = opt[1]
            flags = val[0]
            # name portion after flags+rcode1+rcode2
            return flags, val[3:]
    return None, None


def get_opt(pkt, name):
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == name:
            return opt[1]
    return None


def flags_decode(f):
    if f is None:
        return None
    return {"S": bool(f & F_S), "O": bool(f & F_O),
            "E": bool(f & F_E), "N": bool(f & F_N), "raw": f}


def build_dhcp_opts(msgtype, mode, flags, fqdn, server_id=None, req_ip=None):
    opts = [("message-type", msgtype)]
    if mode == "fqdn":
        opts.append(opt81(flags, fqdn))
    elif mode == "hostname":
        opts.append(("hostname", fqdn.split(".")[0]))
    # mode == "none": no name option at all
    if server_id:
        opts.append(("server_id", server_id))
    if req_ip:
        opts.append(("requested_addr", req_ip))
    opts.append(("param_req_list", [1, 3, 6, 15, 51, 54, 81]))
    opts.append("end")
    return opts


def dora(iface, mac, mode, flags, fqdn, req_ip):
    conf.checkIPaddr = False
    conf.iface = iface
    xid = random.randint(1, 0xFFFFFFFF)
    chaddr = mac_str_to_bytes(mac)
    base = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=chaddr, xid=xid, flags=0x8000))

    disc = base / DHCP(options=build_dhcp_opts("discover", mode, flags, fqdn, req_ip=req_ip))
    offer = srp1(disc, iface=iface, timeout=6, verbose=0)
    if not offer:
        return {"error": "no OFFER"}
    yiaddr = offer[BOOTP].yiaddr
    server_id = get_opt(offer, "server_id")

    req = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
           IP(src="0.0.0.0", dst="255.255.255.255") /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=chaddr, xid=xid, flags=0x8000) /
           DHCP(options=build_dhcp_opts("request", mode, flags, fqdn,
                                        server_id=server_id, req_ip=yiaddr)))
    ack = srp1(req, iface=iface, timeout=6, verbose=0)
    if not ack:
        return {"error": "no ACK", "offered": yiaddr}
    mt = get_opt(ack, "message-type")
    f, name = parse_fqdn_flags(ack)
    return {"assigned_ip": ack[BOOTP].yiaddr, "ack_type": int(mt) if mt else None,
            "reply_fqdn_flags": flags_decode(f),
            "reply_fqdn_name": name.decode("latin1", "replace") if name else None,
            "server_id": server_id}


def renew(iface, mac, mode, flags, fqdn, lease_ip, server_ip):
    """RENEWING-state unicast REQUEST: ciaddr=lease_ip, src=lease_ip, no opt50/54."""
    conf.checkIPaddr = False
    conf.iface = iface
    xid = random.randint(1, 0xFFFFFFFF)
    chaddr = mac_str_to_bytes(mac)
    req = (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
           IP(src=lease_ip, dst="255.255.255.255") /
           UDP(sport=68, dport=67) /
           BOOTP(chaddr=chaddr, xid=xid, ciaddr=lease_ip, flags=0x8000) /
           DHCP(options=build_dhcp_opts("request", mode, flags, fqdn)))
    ack = srp1(req, iface=iface, timeout=6, verbose=0)
    if not ack:
        return {"error": "no ACK (renew)"}
    mt = get_opt(ack, "message-type")
    f, name = parse_fqdn_flags(ack)
    return {"assigned_ip": ack[BOOTP].yiaddr, "ack_type": int(mt) if mt else None,
            "reply_fqdn_flags": flags_decode(f),
            "reply_fqdn_name": name.decode("latin1", "replace") if name else None}


def parse_flags_arg(s):
    if s is None:
        return F_E  # default: E only (S=0, N=0)
    if s.lower().startswith("0x"):
        return int(s, 16)
    f = F_E
    s = s.upper()
    if "S" in s:
        f |= F_S
    if "N" in s:
        f |= F_N
    if "NOE" in s:
        f &= ~F_E
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", default="ens19")
    ap.add_argument("--mac", required=True)
    ap.add_argument("--mode", choices=["fqdn", "hostname", "none"], default="fqdn")
    ap.add_argument("--flags", help="symbolic 'S','N','SN' (E implied) or 0xNN")
    ap.add_argument("--name", default="testhost.dev.plhm.rgn.cm")
    ap.add_argument("--req-ip", default=None)
    ap.add_argument("--renew", action="store_true")
    ap.add_argument("--lease-ip", help="for --renew: current lease IP")
    ap.add_argument("--server-ip", default="192.168.1.1")
    args = ap.parse_args()

    flags = parse_flags_arg(args.flags)
    if args.renew:
        res = renew(args.iface, args.mac, args.mode, flags, args.name,
                    args.lease_ip, args.server_ip)
    else:
        res = dora(args.iface, args.mac, args.mode, flags, args.name, args.req_ip)
    res["sent"] = {"mode": args.mode, "flags": flags_decode(flags) if args.mode == "fqdn" else None,
                   "name": args.name, "mac": args.mac}
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
