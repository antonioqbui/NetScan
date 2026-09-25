class PortResult:
    def __init__(self, port, service, banner, product: str = "No match found", vulnerabilities: list = None):
        self.port = port
        self.service = service
        self.banner = banner
        self.product = product
        self.vulnerabilities = vulnerabilities if vulnerabilities is not None else []
    def __repr__(self):
        return f"Port {self.port} ({self.service}): {self.banner} | Version: {self.product} | Vulnerabilities: {len(self.vulnerabilities)}"
