import argparse
import ipaddress
from typing import Dict, Any, List, Optional


class ArgumentParser:
    def __init__(self):
        self._parser = argparse.ArgumentParser(
            description="Network Port Scanner", add_help=False
        )
        self._setup_arguments()

    def _setup_arguments(self) -> None:
        """Set up all command line arguments."""
        self._parser.add_argument(
            "-h", "--help", action="store_true", help="Show help message"
        )
        self._parser.add_argument(
            "-sr", "--scanner-regular", action="store_true", help="Use regular scanner"
        )
        self._parser.add_argument(
            "-ss", "--scanner-stealth", action="store_true", help="Use stealth scanner"
        )
        self._parser.add_argument("-ip", type=str, help="IPv4 address target")
        self._parser.add_argument("-ipv6", type=str, help="IPv6 address target")
        self._parser.add_argument(
            "-p", "--port", type=int, help="Specific port to scan"
        )
        self._parser.add_argument(
            "-ps", "--port-start", type=int, help="Start of port range"
        )
        self._parser.add_argument(
            "-pe", "--port-end", type=int, help="End of port range"
        )
        self._parser.add_argument(
            "-pp", "--ping", action="store_true", help="Enable ping"
        )
        self._parser.add_argument(
            "-n",
            "--network",
            type=int,
            help="Network mask (e.g., 24 for 255.255.255.0)",
        )

    def parse(self) -> Dict[str, Any]:
        args = self._parser.parse_args()

        args_dict = {
            "help_": args.help,
            "scanner_regular": args.scanner_regular,
            "scanner_stealth": args.scanner_stealth,
            "ip_v4": None,
            "ip_v6": None,
            "port": args.port,
            "port_range": None,
            "ping": args.ping,
            "network_mask": args.network,
        }

        if args.ip:
            try:
                args_dict["ip_v4"] = ipaddress.IPv4Address(args.ip)
            except ValueError:
                print(f"Warning: Invalid IPv4 address: {args.ip}")

        if args.ipv6:
            try:
                args_dict["ip_v6"] = ipaddress.IPv6Address(args.ipv6)
            except ValueError:
                print(f"Warning: Invalid IPv6 address: {args.ipv6}")

        if args.port_start is not None and args.port_end is not None:
            if 0 <= args.port_start <= 65535 and 0 <= args.port_end <= 65535:
                if args.port_start <= args.port_end:
                    args_dict["port_range"] = (args.port_start, args.port_end)
                else:
                    print(
                        "Warning: Port range error: start must be less than or equal to end"
                    )
            else:
                print("Warning: Port values must be between 0 and 65535")

        return args_dict

    def get_help_text(self) -> str:
        help_text = """
Port Scanner Tool
Usage: python main.py [OPTIONS]

Options:
  -h, --help             Show this help message
  -sr, --scanner-regular Use regular TCP scanner
  -ss, --scanner-stealth Use stealth scanner (SYN scan)
  -ip IP                 Target IPv4 address
  -ipv6 IPV6             Target IPv6 address
  -p, --port PORT        Specific port to scan
  -ps, --port-start PORT Start of port range
  -pe, --port-end PORT   End of port range
  -pp, --ping            Enable ping before scanning
  -n, --network MASK     Network mask (e.g., 24 for /24)

Examples:
  python main.py -ip 192.168.1.1 -p 80 -pp
  python main.py -ip 192.168.1.1 -ps 1 -pe 1000 -sr
  python main.py -ip 192.168.1.0 -n 24 -ss
        """
        return help_text
