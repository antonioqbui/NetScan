from models import PortResult


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