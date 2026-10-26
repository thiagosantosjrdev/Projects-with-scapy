from scapy.all import Packet, IP, UDP, DNS, DNSQR, sr1
from ipaddress import ip_address
from urllib.parse import urlparse
import argparse
import random
import re


RCODES = {
    1: "FORMERR (malformed query)",
    2: "SERVFAIL (server failure)",
    3: "NXDOMAIN (domain does not exist)",
    4: "NOTIMP (not implemented)",
    5: "REFUSED (query refused)",
}


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def validate_ip_address(ipaddress_str: str) -> str:
    try:
        ip_address(ipaddress_str)
        return ipaddress_str
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid IP address: {ipaddress_str}")


def validate_domain(domain_str: str) -> str:
    domain_str = domain_str.strip()

    md = re.search(r"\[([^\]]*)\]\(([^)]*)\)", domain_str)
    if md:
        domain_str = md.group(2) or md.group(1)

    if domain_str.startswith("://"):
        domain_str = domain_str[1:]

    if "://" in domain_str:
        domain_str = urlparse(domain_str).hostname or ""
    else:
        domain_str = (
            urlparse(
                domain_str if domain_str.startswith("//") else f"//{domain_str}"
            ).hostname
            or ""
        )

    domain_str = domain_str.rstrip(".").lower()

    if not DOMAIN_RE.fullmatch(domain_str):
        raise argparse.ArgumentTypeError(f"Invalid domain format: {domain_str!r}")
    return domain_str


def validate_port(port_str: str) -> int:
    try:
        port = int(port_str)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Port '{port_str}' must be an integer.")
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(
            f"Port '{port_str}' must be between 1 and 65535."
        )
    return port


def solve_name(domain: str, dns_server: str, sport: int) -> None:
    pkt: Packet = (
        IP(dst=dns_server)
        / UDP(sport=sport, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
    )

    try:
        res: Packet | None = sr1(pkt, timeout=2, verbose=0)
    except PermissionError:
        print("[!] Permissão negada: execute o terminal como administrador/root.")
        return
    except OSError as e:
        print(f"[!] Erro de rede: {e}")
        print("    No Windows, verifique se o Npcap está instalado.")
        return

    if not res or not res.haslayer(DNS):
        print("[-] No response from DNS server (Timeout).")
        return

    dns_layer: DNS = res.getlayer(DNS)

    if dns_layer.rcode != 0:
        print(f"[-] Erro DNS: {RCODES.get(dns_layer.rcode, dns_layer.rcode)}")
        return

    if dns_layer.tc:
        print("[!] Resposta truncada (TC=1); seria necessário repetir via TCP.")

    if dns_layer.ancount == 0:
        print("[-] Domain found, but no records returned.")
        return

    found = False
    for i in range(dns_layer.ancount):
        record = dns_layer.an[i]
        name = record.rrname.decode().rstrip(".")

        if record.type == 1:  # A
            print(f"    -> {name} A {record.rdata}")
            found = True
        elif record.type == 5:  # CNAME
            target = record.rdata
            if isinstance(target, bytes):
                target = target.decode()
            print(f"    -> {name} CNAME {target.rstrip('.')}")

    if found:
        print("[+] Results found (above).")
    else:
        print("[-] No Type A (IPv4) records returned.")


def main(domain: str, dns_server: str, source_port: int) -> None:
    solve_name(domain, dns_server, source_port)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="NsPyLookup",
        description="A simple Python Stub Resolver",
        epilog="Created by thiagosantosjrdev",
    )

    parser.add_argument("domain", help="A domain to solve", type=validate_domain)

    parser.add_argument(
        "-d",
        "--dns",
        help="IP address of the DNS server (default=8.8.8.8)",
        default="8.8.8.8",
        type=validate_ip_address,
    )

    parser.add_argument(
        "-sp",
        "--source-port",
        help="Source port to make the connection (default: random port 1024-65535)",
        default=random.randint(1024, 65535),
        type=validate_port,
    )

    args = parser.parse_args()
    main(args.domain, args.dns, args.source_port)
