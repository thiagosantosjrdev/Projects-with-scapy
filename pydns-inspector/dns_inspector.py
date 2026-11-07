import argparse
import logging
import sys
import validators
from ipaddress import ip_address
from typing import Literal

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.packet import Packet
from scapy.sendrecv import sr1
from random import randint


logging.basicConfig(format="[%(levelname)s] > %(message)s", level=logging.INFO)


def validate_domain(domain: str) -> None:
    if not validators.domain(domain):
        raise ValueError(f"\"{domain}\" isn't a valid format! Try another one.")


def validate_ip_address(c_ip_address: str) -> None:
    try:
        ip_address(c_ip_address)
    except ValueError:
        raise ValueError(f"\"{c_ip_address}\" isn't a valid IPv4! Try another one.")
    if not validators.ipv4(c_ip_address):
        raise ValueError(f"\"{c_ip_address}\" isn't a valid IPv4! Try another one.")


def inspect_dns_packet(pkt: Packet) -> None:
    print("[DNS Inspector]")
    print(f"Transaction ID: {pkt[DNS].id}")
    print(f"Response: {'Response' if pkt[DNS].qr == 1 else 'Query'}")
    print("Response Code: ", end="")
    match pkt[DNS].rcode:
        case 0:
            print("0 (NOERROR)")
        case 1:
            print("1 (FORMERR)")
        case 2:
            print("2 (SERVFAIL)")
        case 3:
            print("3 (NXDOMAIN)")
        case 5:
            print("5 (REFUSED)")
        case _:
            print(f"{pkt[DNS].rcode} (UNKNOWN RCODE)")

    print(f"Questions: {pkt[DNS].qdcount}")
    print(f"Answers: {pkt[DNS].ancount}")
    print(f"Authority: {pkt[DNS].nscount}")
    print(f"Authority Answer: {bool(pkt[DNS].aa)}")
    print(f"Additional: {pkt[DNS].arcount}")

    if pkt[DNS].ancount > 0:
        print("[Answer Records]")
        r_layer = pkt[DNS].an
        for i, c_dnsrr in enumerate(r_layer):
            match c_dnsrr.type:
                case 1:
                    qtype_name = "A"
                case 2:
                    qtype_name = "NS"
                case 5:
                    qtype_name = "CNAME"
                case 6:
                    qtype_name = "SOA"
                case 15:
                    qtype_name = "MX"
                case 28:
                    qtype_name = "AAAA"
                case 41:
                    qtype_name = "OPT"
                case _:
                    qtype_name = "UNKNOWN TYPE"

            print(f"{i:02d} - Type: {c_dnsrr.type}({qtype_name})")
            print(f"     Name: {c_dnsrr.rrname.decode()}")
            print(f"     Data: {c_dnsrr.rdata}")
            print(f"     TTL: {c_dnsrr.ttl}\n")


def main(
    domain: str,
    qtype: Literal["A", "AAAA", "TXT", "MX", "CNAME", "NS", "SOA", "OPT"],
    server_ip: str,
) -> None:

    validate_domain(domain)
    validate_ip_address(server_ip)

    my_port: int = randint(49152, 65535)

    package: Packet = (
        IP(dst=server_ip)
        / UDP(sport=my_port, dport=53)
        / DNS(rd=1, qr=0, qd=DNSQR(qtype=qtype, qname=domain))
    )

    logging.info("Sending DNS query...")
    response: Packet | None = sr1(package, timeout=3, verbose=0)

    if response is None:
        logging.error("No response was received.")
        sys.exit(1)

    if not response.haslayer(DNS):
        logging.error("No valid DNS response was received.")
        sys.exit(1)

    if response.getlayer(UDP).dport != my_port:
        logging.error(
            "A packet with an unexpected destination port was received. "
            "Please try again later."
        )
        sys.exit(1)

    logging.info("DNS response received.")
    inspect_dns_packet(response)


if __name__ == "__main__":
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="Python DNS Inspector",
        description="A simple Python DNS inspector script",
        epilog="Created by thiagosantosjrdev",
    )
    parser.add_argument(
        "domain", help="Domain to inspect", type=str
    )

    parser.add_argument(
        "-t", "--type",
        required=False,
        default="A",
        choices=["A", "AAAA", "TXT", "MX", "CNAME", "NS", "SOA", "OPT"],
        help="DNS query type",
        type=str
    )

    parser.add_argument(
        "--server",
        required=False,
        default="8.8.8.8",
        help="The DNS server to send the query to",
        type=str,
    )

    args = parser.parse_args()

    try:
        main(args.domain, args.type.upper(), args.server)
    except KeyError:
        logging.error(f"O tipo \"{args.type.upper()}\" não existe.")
    except Exception as e:
        logging.error(e)