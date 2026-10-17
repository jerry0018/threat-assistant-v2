"""Authorized-target nmap wrapper. Only loopback and private networks are allowed."""
import ipaddress, shutil, subprocess
import xml.etree.ElementTree as ET


class ScanError(Exception):
    pass


def validate_target(raw):
    """Return a safe target string or raise ScanError."""
    raw = (raw or "").strip()
    if raw.lower() == "localhost":
        return "127.0.0.1"
    try:
        net = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        raise ScanError("Enter an IP address, a CIDR range such as 192.168.1.0/24, or 'localhost'.")
    if not (net.is_private or net.is_loopback):
        raise ScanError("Only private or local addresses can be scanned (for example 192.168.x.x or 127.0.0.1).")
    if net.version != 4:
        raise ScanError("Only IPv4 targets are supported in this version.")
    if net.num_addresses > 256:
        raise ScanError("Range too large. Use /24 or smaller.")
    return str(net)


def run_scan(raw_target):
    target = validate_target(raw_target)
    if not shutil.which("nmap"):
        raise ScanError("nmap is not installed or not on PATH. Install it from https://nmap.org/download")
    # Arguments are passed as a list and never through a shell.
    cmd = ["nmap", "-sT", "-sV", "-T4", "--top-ports", "100", "-oX", "-", target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        raise ScanError("Scan timed out after 5 minutes. Try a single IP.")
    if proc.returncode != 0:
        raise ScanError("nmap failed: " + proc.stderr.strip()[:200])
    return parse_xml(proc.stdout)


def parse_xml(xml_text):
    hosts = []
    for h in ET.fromstring(xml_text).findall("host"):
        if h.find("status") is None or h.find("status").get("state") != "up":
            continue
        addr = h.find("address").get("addr")
        ports = []
        for p in h.findall("./ports/port"):
            if p.find("state").get("state") != "open":
                continue
            svc = p.find("service")
            svc = svc.attrib if svc is not None else {}
            ports.append({"port": int(p.get("portid")), "protocol": p.get("protocol"),
                          "service": svc.get("name", "unknown"),
                          "product": svc.get("product", ""), "version": svc.get("version", "")})
        hosts.append({"address": addr, "ports": ports})
    return hosts
