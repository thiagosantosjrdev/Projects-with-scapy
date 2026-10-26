# NsPyLookup

A simple DNS stub resolver written in Python with [Scapy](https://scapy.net/). It crafts a raw DNS query (type `A`) over UDP, sends it to the DNS server of your choice, and prints the answers.

Built for learning how DNS works at the packet level.

## Features

- Sends raw DNS queries over UDP/53 using Scapy
- Choose the DNS server (default: `8.8.8.8`)
- Choose the source port (default: random port between 1024 and 65535)
- Accepts a plain domain, a full URL, or a pasted link and extracts the hostname automatically
- Displays `A` and `CNAME` records from the answer section
- Reports DNS errors (`NXDOMAIN`, `SERVFAIL`, `REFUSED`, etc.), timeouts, and truncated responses

## Requirements

- Python 3.10+
- [Scapy](https://pypi.org/project/scapy/)
- **Windows:** [Npcap](https://npcap.com) installed
- **Linux/macOS:** root privileges (raw sockets)

## Installation

```bash
git clone https://github.com/<your-username>/NsPyLookup.git
cd NsPyLookup
pip install scapy
```

## Usage

```
python main.py [-h] [-d DNS] [-sp SOURCE_PORT] domain
```

| Argument | Description | Default |
|---|---|---|
| `domain` | Domain to resolve (also accepts URLs such as `https://example.com/path`) | required |
| `-d`, `--dns` | IP address of the DNS server | `8.8.8.8` |
| `-sp`, `--source-port` | Source UDP port (1-65535) | random (1024-65535) |
| `-h`, `--help` | Show the help message | |

### Examples

```bash
# Basic lookup using Google DNS
python main.py example.com

# Use Cloudflare DNS
python main.py example.com -d 1.1.1.1

# Use a specific source port
python main.py example.com -sp 40000

# Full URLs are accepted (quote them in PowerShell/Bash)
python main.py "https://www.example.com/some/path"
```

On Linux/macOS, run with `sudo`:

```bash
sudo python3 main.py example.com
```

On Windows, open the terminal as Administrator if you get a permission error.

### Sample output

```
    -> www.example.com CNAME example.com
    -> example.com A 93.184.216.34
[+] Results found (above).
```

Error examples:

```
[-] Erro DNS: NXDOMAIN (domínio não existe)
[-] No response from DNS server (Timeout).
```

## How it works

1. The input is validated and the hostname is extracted (scheme, port, path and trailing dot are removed).
2. A packet is built with Scapy: `IP / UDP / DNS(rd=1, qd=DNSQR(qtype="A"))`.
3. The packet is sent with `sr1()` and the first reply is captured (2 second timeout).
4. The response code is checked and the answer records are printed.

## Limitations

- IPv4 (`A`) lookups only
- No automatic TCP fallback when the response is truncated (`TC=1`)
- No retries; a single query is sent
- Not a replacement for `dig` or `nslookup`

## Disclaimer

This project is intended for educational purposes. Only send queries to DNS servers you are allowed to use.

## License

MIT (add a `LICENSE` file to the repository if you choose this license).

---

Created by [thiagosantosjrdev](https://github.com/thiagosantosjrdev)