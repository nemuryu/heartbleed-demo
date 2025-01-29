# Heartbleed Exploit Script

## Overview
This repository contains a Python script that exploits the Heartbleed vulnerability (CVE-2014-0160). The script was developed as part of a seminar paper on software security for a course titled **Cybersecurity**.

> **Disclaimer:** This script is for educational and research purposes only. Unauthorized use against systems without explicit permission is illegal and unethical. The author assumes no liability for any misuse of this code.

## Prerequisites
To run the script, ensure you have Python 3.x installed!

## Usage
Run the script with the target server's IP and port:
```bash
python heartbleed.py <target_ip> -p <port>
```
Example:
```bash
python heartbleed.py 192.168.100.4 -p 8443
```

## How It Works
1. Establishes a TLS connection with the target
2. Sends a malformed Heartbeat request to trick the server into leaking memory
3. Captures and displays the leaked data (which may include private keys, passwords, and other sensitive data)

## References
- [Heartbleed Vulnerability (CVE-2014-0160)](https://heartbleed.com/)
- [OpenSSL Security Advisory](https://www.openssl.org/news/secadv/20140407.txt)
