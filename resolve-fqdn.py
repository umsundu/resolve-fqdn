import socket
import argparse
import sys

def resolve_fqdn(ip_list):
    resolved_hosts = {}
    for ip in ip_list:
        try:
            fqdn = socket.gethostbyaddr(ip)[0]
            resolved_hosts[ip] = fqdn
        except socket.herror:
            resolved_hosts[ip] = "Unable to resolve"
    return resolved_hosts

def load_ips_from_file(filename):
    try:
        with open(filename, 'r') as file:
            ip_addresses = [line.strip() for line in file if line.strip()]
        return ip_addresses
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Resolve FQDNs for a list of IP addresses."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-i", "--ips",
        metavar="IP",
        nargs="+",
        help="List of IP addresses to resolve"
    )
    group.add_argument(
        "-f", "--file",
        metavar="FILENAME",
        help="File containing IP addresses (one per line)"
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Load IP addresses from file or command-line arguments
    if args.file:
        ip_addresses = load_ips_from_file(args.file)
    else:
        ip_addresses = args.ips
    
    # Resolve IPs to FQDNs
    resolved_dict = resolve_fqdn(ip_addresses)
    
    # Display results neatly
    print("\nResolved FQDNs:")
    for ip, fqdn in resolved_dict.items():
        print(f"{fqdn}: {ip}")

if __name__ == "__main__":
    main()
