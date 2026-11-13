#!/usr/bin/env python3
"""Create or verify the bounded infrastructure scan profile over local GMP.

The password is accepted only on stdin. This script never starts a scan.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import socket
import sys
import xml.etree.ElementTree as ET


PROFILE_NAME = "IT4US Infra Only v2"
SELECTED_FAMILIES = frozenset({
    "CISCO", "Databases", "F5 Local Security Checks", "FTP",
    "FortiOS Local Security Checks", "Huawei",
    "JunOS Local Security Checks", "Palo Alto PAN-OS Local Security Checks",
    "RPC", "Remote file access",
    "SMTP problems", "SNMP", "SSL and TLS", "Service detection",
    "Settings", "Useless services", "Windows",
})


class GMP:
    def __init__(self, password: str, username: str = "admin", address: str = "127.0.0.1:9390") -> None:
        host, port_text = address.rsplit(":", 1)
        if ipaddress.ip_address(host) != ipaddress.ip_address("127.0.0.1"):
            raise ValueError("GMP must use local loopback")
        self.sock = socket.create_connection((host, int(port_text)), timeout=5)
        self.sock.settimeout(30)
        auth = ET.Element("authenticate")
        credentials = ET.SubElement(auth, "credentials")
        ET.SubElement(credentials, "username").text = username
        ET.SubElement(credentials, "password").text = password
        self.call(auth)

    def close(self) -> None:
        self.sock.close()

    def call(self, command: ET.Element) -> ET.Element:
        self.sock.sendall(ET.tostring(command, encoding="utf-8"))
        parser = ET.XMLPullParser(events=("start", "end"))
        depth = 0
        length = 0
        while True:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("GMP connection closed")
            length += len(chunk)
            if length > 8 << 20:
                raise RuntimeError("GMP response too large")
            parser.feed(chunk)
            for event, node in parser.read_events():
                depth += 1 if event == "start" else -1
                if event == "end" and depth == 0:
                    status = int(node.get("status", "0"))
                    if status < 200 or status >= 300:
                        raise RuntimeError(f"GMP {node.tag} status {status}: {node.get('status_text', '')[:160]}")
                    return node


def get_config(gmp: GMP, config_id: str) -> ET.Element:
    response = gmp.call(ET.Element("get_configs", {"config_id": config_id, "details": "1"}))
    config = response.find("config")
    if config is None:
        raise RuntimeError("scan profile not found")
    return config


def verify_profile(config: ET.Element) -> tuple[int, int]:
    families = {item.findtext("name") for item in config.findall("./families/family")}
    if families != SELECTED_FAMILIES:
        raise RuntimeError("scan profile family selection differs from the infrastructure allowlist")
    preferences = config.findall("./preferences/preference")
    safe_checks = [p.findtext("value") for p in preferences if p.findtext("name") == "safe_checks"]
    if safe_checks != ["1"]:
        raise RuntimeError("scan profile must enable safe_checks")
    return len(families), int(config.findtext("nvt_count") or "0")


def main() -> int:
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--password-stdin", action="store_true")
    args.add_argument("--address", default="127.0.0.1:9390")
    parsed = args.parse_args()
    password = sys.stdin.readline().rstrip("\r\n") if parsed.password_stdin else getpass.getpass("GMP password: ")
    if not password:
        raise ValueError("GMP password required")
    gmp = GMP(password, address=parsed.address)
    try:
        response = gmp.call(ET.Element("get_configs", {"filter": "rows=-1"}))
        existing = {c.findtext("name"): c.get("id") for c in response.findall("config")}
        config_id = existing.get(PROFILE_NAME)
        if not config_id:
            source = existing.get("empty")
            if not source:
                raise RuntimeError("empty feed profile not imported yet")
            command = ET.Element("create_config")
            ET.SubElement(command, "copy").text = source
            ET.SubElement(command, "name").text = PROFILE_NAME
            ET.SubElement(command, "comment").text = "Scoped infrastructure VTs; safe_checks enabled; no application, general, product detection, brute force or DoS family"
            config_id = gmp.call(command).get("id")
            if not config_id:
                raise RuntimeError("manager did not return a profile ID")
            command = ET.Element("modify_config", {"config_id": config_id})
            selection = ET.SubElement(command, "family_selection")
            ET.SubElement(selection, "growing").text = "0"
            for name in sorted(SELECTED_FAMILIES):
                family = ET.SubElement(selection, "family")
                ET.SubElement(family, "name").text = name
                ET.SubElement(family, "all").text = "1"
                ET.SubElement(family, "growing").text = "1"
            gmp.call(command)
        family_count, nvt_count = verify_profile(get_config(gmp, config_id))
        scanners = gmp.call(ET.Element("get_scanners"))
        scanner_id = next((item.get("id") for item in scanners.findall("scanner")
                           if item.findtext("name") == "OpenVAS Default"), None)
        if not scanner_id:
            raise RuntimeError("OpenVAS Default scanner not available")
        print(f"profile_id={config_id}")
        print(f"scanner_id={scanner_id}")
        print(f"families={family_count} nvts={nvt_count} safe_checks=1")
        return 0
    finally:
        gmp.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"profile setup failed: {error}", file=sys.stderr)
        raise SystemExit(1)
