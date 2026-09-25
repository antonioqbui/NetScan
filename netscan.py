from scanner import scan_host
from fingerprint import (
    grab_banner,
    identify_service,
    probe_http,
    extract_server_header,
    extract_product_versions
)
from vulnerability import lookup_cve
from report import generate_report
from models import PortResult




def confirm_authorization(host: str) -> bool:
    response = input(f"Do you have permission to scan {host}? y/n ")
    if response.lower() in ["y", "yes"]:
        return True
    else:
        return False
    



def main():
    host = input("Target host: ")
    start_port = input("Starting port [1]: ")
    end_port = input("Ending port [1024]: ")
    output = input("Output filename [report.txt]: ")

    start_port = int(start_port) if start_port else 1
    end_port = int(end_port) if end_port else 1024
    output = output if output else "report.txt"

    if confirm_authorization(host):
        results = scan_host(host, start_port, end_port)
        generate_report(results, output)
        print(f"Scan complete. Report saved to {output}")
    else:
        print("Authorization not confirmed. Exiting.")


if __name__ == "__main__":
    main() 