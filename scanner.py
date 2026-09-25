import socket
from concurrent.futures import ThreadPoolExecutor

from constants import COMMON_PORTS
from models import PortResult
from fingerprint import (
    identify_service,
    grab_banner,
    probe_http,
    extract_server_header,
    extract_product_versions
)
from vulnerability import lookup_cve


# Scans the port from the host and returns a boolean true if a connection is made
def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_socket.settimeout(timeout)
    result = new_socket.connect_ex((host, port))
    new_socket.close()
    if result == 0:
        return True
    else:
        return False

# Port Scanner using ThreadPoolExecutor to quickly go through the range and test if port is open
def scan_range_threaded(host: str, start_port: int, end_port: int, timeout: float = 1.0) -> list:
    open_ports = []
    ports_range = range(start_port, end_port + 1)
    scan_fixed_args = lambda port: scan_port(host, port, timeout)
    with ThreadPoolExecutor(max_workers=200) as ports:
        results = ports.map(scan_fixed_args, ports_range)
        results_format = zip(ports_range, results)
        for port, is_open in results_format:
            if is_open == True:
                open_ports.append(port)
    return open_ports

def scan_host(host: str, start_port: int, end_port: int, timeout: float = 1.0) -> list:
    open_ports = scan_range_threaded(host, start_port, end_port, timeout)

    port_results = []

    for port in open_ports:
        service = identify_service(port)
        banner = grab_banner(host, port, timeout)
        if "HTTP" in service:
            raw_response = probe_http(host, port, timeout)
            server_header = extract_server_header(raw_response)
            product_versions = extract_product_versions(server_header)

            all_cves = []
            product_summary = []

            for product, version in product_versions:
                cve_matches = lookup_cve(product, version)
                all_cves.extend(cve_matches)
                product_summary.append(f"{product} {version}")

            product_str = ", ".join(product_summary) if product_summary else "Unknown"
            current_port = PortResult(port, service, banner, product_str, all_cves)
        else:
            current_port = PortResult(port, service, banner)

        port_results.append(current_port)

    return port_results