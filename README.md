# NetVulnScan

NetVulnScan is a simple network vulnerability scanner written in Python using the Scapy library. It scans a specified IP range for active hosts and checks for open ports on those hosts.

## Features

- Scans a specified IP range for active hosts using ARP requests.
- Scans the first 1024 TCP ports on each active host to identify open ports.

## Requirements

- Python 3.x
- Scapy library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/A1J-AY/NetVulnScan.git
   cd NetVulnScan

3. Install the required dependencies:
   ```bash
   pip install scapy

## Usage

python NetVulnScan.py
When prompted, enter the IP range you want to scan (e.g., 192.168.1.1/24).

## Example
```bash
Enter the IP range to scan (e.g., 192.168.1.1/24): 192.168.1.1/24
Scanning for active hosts...
Active hosts found:
192.168.1.1
Open ports on 192.168.1.1: [22, 80]


