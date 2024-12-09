#!/usr/bin/env python3

import nmap
import sys
import os
from datetime import datetime

def usage():
    print("Usage: python3 nmap_full_report.py <target_ip_or_hostname>")
    print("Example: python3 nmap_full_report.py example.com")
    sys.exit(1)

def create_report_directory():
    report_dir = "nmap_reports"
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)
    return report_dir

def generate_report(target, scan_data, report_dir):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    sanitized_target = target.replace('/', '_').replace('\\', '_')
    report_filename = f"{report_dir}/{sanitized_target}_{timestamp}.txt"
    
    with open(report_filename, 'w') as report_file:
        report_file.write(f"Nmap Full Scan Report for {target}\n")
        report_file.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Host Information
        if 'host' in scan_data:
            host = scan_data['host']
            report_file.write("=== Host Information ===\n")
            report_file.write(f"Status: {host['status']['state']}\n")
            if 'addresses' in host:
                for addr_type, addr in host['addresses'].items():
                    report_file.write(f"{addr_type.capitalize()}: {addr}\n")
            if 'hostnames' in host and host['hostnames']:
                report_file.write("Hostnames:\n")
                for hostname in host['hostnames']:
                    report_file.write(f" - {hostname['name']} ({hostname['type']})\n")
            if 'osmatch' in host and host['osmatch']:
                report_file.write("\nOS Detection:\n")
                for os in host['osmatch']:
                    report_file.write(f"Name: {os['name']}, Accuracy: {os['accuracy']}%\n")
            report_file.write("\n")
        
        # Port Information
        if 'tcp' in scan_data:
            report_file.write("=== Open TCP Ports ===\n")
            for port, port_data in scan_data['tcp'].items():
                report_file.write(f"Port: {port}/tcp\n")
                report_file.write(f"State: {port_data['state']}\n")
                report_file.write(f"Service: {port_data['name']}\n")
                report_file.write(f"Version: {port_data.get('version', 'N/A')}\n")
                # Script Outputs
                if 'script' in port_data and port_data['script']:
                    report_file.write("Scripts Output:\n")
                    for script, output in port_data['script'].items():
                        report_file.write(f"  [{script}]: {output}\n")
                report_file.write("\n")
        
        if 'udp' in scan_data:
            report_file.write("=== Open UDP Ports ===\n")
            for port, port_data in scan_data['udp'].items():
                report_file.write(f"Port: {port}/udp\n")
                report_file.write(f"State: {port_data['state']}\n")
                report_file.write(f"Service: {port_data['name']}\n")
                report_file.write(f"Version: {port_data.get('version', 'N/A')}\n")
                # Script Outputs
                if 'script' in port_data and port_data['script']:
                    report_file.write("Scripts Output:\n")
                    for script, output in port_data['script'].items():
                        report_file.write(f"  [{script}]: {output}\n")
                report_file.write("\n")
        
        # Host Scripts (if any)
        if 'hostscript' in scan_data:
            report_file.write("=== Host Scripts Output ===\n")
            for script in scan_data['hostscript']:
                report_file.write(f"Script: {script['id']}\n")
                report_file.write(f"Output: {script['output']}\n\n")
        
        print(f"Report generated: {report_filename}")

def main():
    if len(sys.argv) != 2:
        usage()
    
    target = sys.argv[1]
    print(f"Starting Nmap full scan on {target}...")
    
    # Initialize the PortScanner
    nm = nmap.PortScanner()
    
    # Define common ports (both standard and database-related)
    # You can modify the port list as needed
    ports = '21,22,23,25,53,80,110,135,139,143,443,445,3306,3389,5432,5900,6379,8080,8443'
    
    # Define NSE scripts for database detection and other info
    # These scripts can be expanded based on requirements
    scripts = [
        'mysql-info',
        'pgsql-info',
        'mssql-info',
        'oracle-sid-brute',
        'mongodb-info',
        'redis-info',
        'http-title',
        'http-enum',
        'ssl-cert',
        'ssl-enum-ciphers'
    ]
    scripts_str = ','.join(scripts)
    
    # Combine arguments: service/version detection, OS detection, specific scripts
    nmap_args = f'-sV -O --script {scripts_str}'
    
    try:
        # Perform the scan
        nm.scan(target, ports=ports, arguments=nmap_args)
    except Exception as e:
        print(f"An error occurred while scanning: {e}")
        sys.exit(1)
    
    # Check if target was scanned
    if target not in nm.all_hosts():
        print(f"No information available for target: {target}")
        sys.exit(1)
    
    scan_data = nm[target]
    
    # Create report directory
    report_dir = create_report_directory()
    
    # Generate report
    generate_report(target, scan_data, report_dir)

if __name__ == "__main__":
    main()
