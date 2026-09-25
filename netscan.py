import socket
from concurrent.futures import ThreadPoolExecutor
import re
import requests
import argparse

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Alt",
}


class PortResult:
    def __init__(self, port, service, banner, product: str = "No match found", vulnerabilities: list = None):
        self.port = port
        self.service = service
        self.banner = banner
        self.product = product
        self.vulnerabilities = vulnerabilities if vulnerabilities is not None else []
    def __repr__(self):
        return f"Port {self.port} ({self.service}): {self.banner} | Version: {self.product} | Vulnerabilities: {len(self.vulnerabilities)}"



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


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_socket.settimeout(timeout)
    result = new_socket.connect_ex((host, port))
    if result != 0:
        new_socket.close()
        return "Connection Refused"
    try:
        banner_bytes = new_socket.recv(1024)
    except socket.timeout:
        new_socket.close()
        return "No Banner"
    new_socket.close()
    return banner_bytes.decode('utf-8', errors='ignore')

def identify_service(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown")


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
def probe_http(host: str, port: int, timeout: float = 2.0) -> str:
    new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_socket.settimeout(timeout)
    result = new_socket.connect_ex((host, port))
    if result != 0:
        new_socket.close()
        return "Connection Refused"
    request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    new_socket.sendall(request.encode())
    full_response = b""
    try:
        while True:
            byte_chunk = new_socket.recv(4096)
            if not byte_chunk:
                break
            full_response += byte_chunk
    except socket.timeout:
        pass

    new_socket.close()
    return full_response.decode('utf-8', errors='ignore')

def extract_server_header(response_text: str) -> str:
    lines = response_text.split("\r\n")
    for response_line in lines:
        if (response_line.startswith("Server: ")):
            parts = response_line.split(": ")
            return parts[1]
        else:
            pass
    return "Unknown"


def extract_version_number(server_value: str) -> str:
    match = re.search(r"\d+\.\d+(?:\.\d+)?", server_value)
    if match is None:
        return "No match found"
    else:
        return match.group()


# KNOWN LIMITATION: version matching uses substring search on CVE descriptions
# and can produce false positives, e.g. searching "1.18" incorrectly matched
# CVE-2012-2089 (nginx 1.1.18, a different version) and CVEs about unrelated
# software (Rack) that happened to mention nginx or share matching digits.
# A production tool would use CPE-based structured version-range matching
# instead of text search.
def lookup_cve(product: str, version: str) -> list:
    response = requests.get(
    "https://services.nvd.nist.gov/rest/json/cves/2.0",
    params={"keywordSearch": f"{product}"}
    )
    data = response.json()
    matching = []
    for entry in data["vulnerabilities"]:
        cve_data = entry["cve"]
        description = cve_data["descriptions"][0]["value"]
        if major_minor_version(version) in description:
            metrics = cve_data["metrics"]
            score = extract_cvss_score(metrics)
            risk_level = score_to_risk_level(score)
            match = {"id": cve_data["id"], "description": description,"score": score ,"risk_level": risk_level}
            matching.append(match)
    return matching

def major_minor_version(version: str) -> str:
    parts = version.split(".")
    return f"{parts[0]}.{parts[1]}"

def extract_cvss_score(metrics: dict) -> float:
    possible_keys = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]
    for key in possible_keys:
        if key in metrics:
            basescore = metrics[key][0]['cvssData']['baseScore']
            return float(basescore)
    return 0.0

def score_to_risk_level(score: float) -> str:
    if score == 0.0:
        return "None"
    elif score >= 0.1 and score <= 3.9:
        return "Low"
    elif score >= 4.0 and score <= 6.9:
        return "Medium"
    elif score >= 7.0 and score <= 8.9:
        return "High"
    elif score >= 9.0:
        return "Critical"
    else:
        return "Unknown"

def extract_product_versions(server_value: str) -> list:
        return re.findall(r"([A-Za-z][A-Za-z0-9_-]*)/(\d+(?:\.\d+)*)", server_value)

def format_port_result(result: PortResult) -> str: 

    port = f"Port: {result.port}"
    service = f"Service: {result.service}"
    product = f"Product: {result.product}"
    vulnerabilities = f"Vulnerabilities: ({len(result.vulnerabilities)})"
    vuln_lines = []
    sorted_vulns = sorted(result.vulnerabilities, key=lambda vuln: vuln["score"], reverse=True)
    for vuln in sorted_vulns:
        line = f"{vuln['id']} | CVSS: {vuln['score']} | Risk: {vuln['risk_level']}"
        vuln_lines.append(line)
    final = [port, service, product, vulnerabilities] + vuln_lines
    format_string = "\n".join(final)
    return format_string


def generate_report(results: list, filename: str = "report.txt") -> None:
    with open(filename, "w") as file:
        for portresult in results:
            file.write(format_port_result(portresult) + "\n\n")
            file.write("\n\n")

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