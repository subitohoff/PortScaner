from socket import gethostbyname, gaierror
from typing import Any
from ipaddress import IPv4Address
import sys

from util.argument_parser import ArgumentParser
from core.scan_manager import ScanManager
from core.scanners.scanner import ScanType


def check_args(args: dict[str, Any]):
    if not args["ip_v4"] and not args["ip_v6"] and not args["domain"]:
        print(
            "Error: No target specified. Please provide an IP address with -ip, -ipv6, -d."
        )
        print("Use -h for help.")
        sys.exit()

    if not args["port"] and not args["port_range"]:
        print(
            "Error: No ports specified. "
            "Please provide a port with -p or a port range with -ps and -pe."
        )
        print("Use -h for help.")
        sys.exit()
    return True


def parse_ports(port_str: str) -> tuple[bool, list[int]]:
    is_range: bool
    ports: list = []
    if port_str.find(",") != -1:
        try:
            ports = [int(s) for s in port_str.split(",")]
        except ValueError:
            print(f"Invalid ports: {port_str}")
            sys.exit(1)
        is_range = False
    elif port_str.find("-"):
        try:
            ports = [int(s) for s in port_str.split("-")]
            if len(ports) != 2:
                raise ValueError
        except ValueError:
            print(f"Invalid port range: {port_str}")
            sys.exit(1)
        is_range = True
    return is_range, ports


def print_configuration(args: dict[str, Any], scanner_type):
    print("Scan Configuration:")
    print(f"  Scanner Type: {scanner_type}")
    if args["ip_v4"]:
        print(f"  IPv4 Target: {args['ip_v4']}")
    if args["ip_v6"]:
        print(f"  IPv6 Target: {args['ip_v6']}")
    if args["domain"]:
        print(f"  Target domain: {args['domain']}")
    if args["port"]:
        print(f"  Ports: {args['port']}")
    if args["port_range"] != (0, 0):
        print(f"  Port Range: {args['port_range'][0]}-{args['port_range'][1]}")
    if args["ping"]:
        print("  Ping: Enabled")
    if args["network_mask"]:
        print(f"  Network Mask: /{args['network_mask']}")


def main():
    arg_parser = ArgumentParser()
    args = arg_parser.parse()

    if args["help_"]:
        print(arg_parser.get_help_text())
        return

    check_args(args)

    scanner_type = "stealth" if args["scanner_stealth"] else "regular"

    print_configuration(args, scanner_type)

    manager = ScanManager(
        scan_type=ScanType.SYN if args["scanner_stealth"] else ScanType.TCP,
        do_ping=args["ping"],
        threads=1,
    )

    if args["ip_v4"]:
        manager.add_target_host(args["ip_v4"])
    if args["ip_v6"]:
        manager.add_target_host(args["ip_v6"])
    if args["domain"]:
        try:
            manager.add_target_host(IPv4Address(gethostbyname(args["domain"])))
        except gaierror:
            print(f"Hostname {args['domain']} not found!")
            if not args["ip_v4"] and not args["ip_v6"]:
                return

    if args["port"]:
        is_range, ports = parse_ports(args["port"])
        if is_range:
            manager.set_target_port_range(*ports)
        else:
            manager.set_target_ports(ports)
    elif args["port_range"] != (0, 0):
        manager.set_target_port_range(*args["port_range"])

    manager.scan_all()

    for result in manager.get_results():
        print(result)


if __name__ == "__main__":
    main()
