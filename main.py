#!/usr/bin/env python3
import argparse
import json
import os
import sys
from datetime import datetime
from tabulate import tabulate
from scanners.lan_scanner import scan_network, get_local_network
from scanners.wan_scanner import scan_target, scan_range, ScannerConfig
from typing import Dict

def parse_args():
    parser = argparse.ArgumentParser(description='IoT Network Scanner')
    parser.add_argument('mode', choices=['lan', 'wan'], help='Scanning mode (lan/wan)')
    parser.add_argument('-r', '--range', help='IP range to scan (e.g., 192.168.1.0/24 or 1.1.1.1-1.1.1.5)')
    parser.add_argument('-t', '--target', help='Single target to scan (IP or hostname)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout in seconds')
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum number of concurrent workers')
    parser.add_argument('--no-ssl', action='store_true', help='Disable SSL/TLS scanning')
    return parser.parse_args()

def display_results(results: Dict) -> None:
    """Display scan results in a formatted table."""
    if not results:
        print("No results to display.")
        return

    if isinstance(results, list):
        # Handle multiple results (range scan)
        table_data = []
        for result in results:
            # Get status with fallback to 'state' or 'unknown'
            status = result.get('status', result.get('state', 'unknown'))
            
            # Only show active hosts in the table
            if status == 'up':
                ports = result.get('ports', [])
                services = result.get('services', [])
                
                # Format ports and services
                ports_str = ', '.join(str(p) for p in ports) if ports else 'None'
                services_str = ', '.join(s.get('name', 'unknown') for s in services) if services else 'None'
                
                table_data.append([
                    result.get('target', result.get('ip', 'Unknown')),
                    status,
                    ports_str,
                    services_str,
                    result.get('vendor', 'Unknown'),
                    result.get('risk_level', 'Unknown')
                ])
        
        if table_data:
            print("\nScan Results:")
            print(tabulate(
                table_data,
                headers=['Target', 'Status', 'Open Ports', 'Services', 'Vendor', 'Risk Level'],
                tablefmt='grid'
            ))
        else:
            print("\nNo active hosts found.")
    else:
        # Handle single result
        status = results.get('status', results.get('state', 'unknown'))
        target = results.get('target', results.get('ip', 'Unknown'))
        
        print(f"\nTarget: {target}")
        print(f"Status: {status}")
        
        if status == 'up':
            ports = results.get('ports', [])
            services = results.get('services', [])
            
            if ports:
                print("\nOpen Ports:")
                for port, service in zip(ports, services):
                    service_name = service.get('name', 'unknown')
                    print(f"  {port}/tcp - {service_name}")
                    if service.get('banner'):
                        print(f"    Banner: {service['banner'][:100]}...")
            
            print(f"\nVendor: {results.get('vendor', 'Unknown')}")
            print(f"Risk Level: {results.get('risk_level', 'Unknown')}")
            
            if results.get('default_creds'):
                print("\nDefault Credentials Found:")
                for cred in results['default_creds']:
                    username = cred.get('username', 'unknown')
                    password = cred.get('password', 'unknown')
                    print(f"  {username}:{password}")
        else:
            if results.get('errors'):
                print("\nErrors:")
                for error in results['errors']:
                    print(f"  {error}")

def save_results(results, output_file=None):
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"reports/scan_{timestamp}.json"
    
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {output_file}")

def main():
    args = parse_args()
    
    # Create scanner configuration
    config = ScannerConfig(
        timeout=args.timeout,
        max_workers=args.max_workers,
        use_ssl=not args.no_ssl,
        verbose=args.verbose
    )

    try:
        if args.mode == 'lan':
            if args.target:
                print(f"Scanning single LAN IP: {args.target}")
                results = scan_target(args.target, config)
            else:
                if not args.range:
                    args.range = get_local_network()
                    print(f"Using local network: {args.range}")
                results = scan_network(args.range, verbose=args.verbose)
        
        else:  # WAN mode
            if args.target:
                results = scan_target(args.target, config)
            elif args.range:
                results = scan_range(args.range, config)
            else:
                print("Error: For WAN scanning, either --target or --range must be specified")
                sys.exit(1)

        display_results(results)
        save_results(results, args.output)

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

        
        display_results(results)
        save_results(results, args.output)
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
