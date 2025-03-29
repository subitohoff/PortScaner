from core.argument_parser import ArgumentParser


def main():
    
    
    
    arg_parser = ArgumentParser()
    args = arg_parser.parse()
    

    if args['help_']:
        print(arg_parser.get_help_text())
        return
    

    if not args['ip_v4'] and not args['ip_v6']:
        print("Error: No target specified. Please provide an IP address with -ip or -ipv6.")
        print("Use -h for help.")
        return
    

    if not args['port'] and not args['port_range']:
        print("Error: No ports specified. Please provide a port with -p or a port range with -ps and -pe.")
        print("Use -h for help.")
        return
    

    scanner_type = "regular" 
    if args['scanner_stealth']:
        scanner_type = "stealth"
    elif args['scanner_regular']:
        scanner_type = "regular"
    

    print("Scan Configuration:")
    print(f"  Scanner Type: {scanner_type}")
    if args['ip_v4']:
        print(f"  IPv4 Target: {args['ip_v4']}")
    if args['ip_v6']:
        print(f"  IPv6 Target: {args['ip_v6']}")
    if args['port']:
        print(f"  Port: {args['port']}")
    if args['port_range']:
        print(f"  Port Range: {args['port_range'][0]}-{args['port_range'][1]}")
    if args['ping']:
        print("  Ping: Enabled")
    if args['network_mask']:
        print(f"  Network Mask: /{args['network_mask']}")
    
    #tu podac dalej arg do menadzera 


if __name__ == "__main__":
    main()
