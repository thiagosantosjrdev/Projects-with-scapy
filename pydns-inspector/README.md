# PyDNS Inspector

A lightweight DNS query and response inspector built with Python and Scapy.

PyDNS Inspector sends DNS queries to a specified DNS server and displays useful information about the received DNS response, including its transaction ID, response code, DNS sections, and answer records.

## Features

- DNS queries over UDP
- Custom DNS server selection
- Support for multiple DNS record types
- DNS response inspection
- Transaction ID and response code display
- Answer record information, including name, type, data, and TTL
- Domain and IPv4 address validation
- Command-line interface using `argparse`
- Logging with different severity levels

## Supported DNS Record Types

| Type | Description |
|---|---|
| A | IPv4 address |
| AAAA | IPv6 address |
| TXT | Text record |
| MX | Mail exchange |
| CNAME | Canonical name |
| NS | Name server |
| SOA | Start of Authority |
| OPT | EDNS pseudo-record |

## Requirements

- Python 3.10 or newer
- Scapy
- Validators

Administrative privileges may be required to send raw packets with Scapy.

## Installation

Clone the repository:

```bash
git clone https://github.com/thiagosantosjrdev/pydns-inspector.git
cd pydns-inspector
```

Install the dependencies:

```bash
pip install -r requirements.txt
```

## Usage

### Basic DNS query

```bash
python dns_inspector.py example.com
```

By default, the script queries the DNS server `8.8.8.8` for an A record.

### Specify a DNS record type

```bash
python dns_inspector.py example.com --type AAAA
```

Short option:

```bash
python dns_inspector.py example.com -t MX
```

### Specify a DNS server

```bash
python dns_inspector.py example.com --server 1.1.1.1
```

### Combine options

```bash
python dns_inspector.py example.com --type A --server 1.1.1.1
```

## Example Output

```text
[INFO] > Sending DNS query...
[INFO] > DNS response received.
[DNS Inspector]
Transaction ID: 0
Response: Response
Response Code: 0 (NOERROR)
Questions: 1
Answers: 2
Authority: 0
Authority Answer: False
Additional: 0
[Answer Records]
00 - Type: 1(A)
     Name: example.com.
     Data: 104.20.23.154
     TTL: 236

01 - Type: 1(A)
     Name: example.com.
     Data: 172.66.147.243
     TTL: 236
```

*The values above are illustrative and may differ depending on the DNS response.*

## Disclaimer

This project was created for educational purposes and to explore DNS packet inspection using Python and Scapy.

Use it responsibly and only against DNS servers you are authorized to query.

## Author

Created by [thiagosantosjrdev](https://github.com/thiagosantosjrdev)