import scapy.all as scapy
import socket
import sys

def scan(ip_range):
    # ARP request to find active hosts
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    active_hosts = []
    for element in answered_list:
        active_hosts.append(element[1].psrc)
    
    return active_hosts

def scan_ports(ip):
    open_ports = []
    for port in range(1, 1025):  # Scanning first 1024 ports
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
    return open_ports

def main():
    ip_range = input("Enter the IP range to scan (e.g., 192.168.1.1/24): ")
    
    print("Scanning for active hosts...")
    active_hosts = scan(ip_range)
    
    if not active_hosts:
        print("No active hosts found.")
        return

    print("\nActive hosts found:")
    for host in active_hosts:
        print(f" - {host}")
        open_ports = scan_ports(host)
        if open_ports:
            print(f"   Open ports: {open_ports}")
        else:
            print("   No open ports found.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
