NetScan



NetScan is a Python-based network vulnerability scanner designed to identify open ports, detect services, fingerprint HTTP software versions, and search the NVD for potential CVE matches.



Features

Concurrent TCP port scanning using ThreadPoolExecutor

Common service identification based on port numbers

TCP banner grabbing

HTTP service probing

HTTP Server header extraction

Software and version detection using regular expressions

NVD CVE lookup

CVSS score extraction and risk classification

Text-based vulnerability reports

Interactive command-line input

Authorization confirmation before scanning

Technologies

Python

Socket programming

ThreadPoolExecutor

Regular expressions

HTTP requests

NVD API

How It Works



NetScan performs the following steps:



Prompts the user for a target host and port range.

Confirms that the user has permission to scan the target.

Scans the specified ports concurrently.

Identifies open ports and maps common ports to their associated services.

Attempts to grab service banners from open ports.

Probes HTTP services and extracts the Server header.

Identifies software products and versions from the HTTP response.

Queries the NIST National Vulnerability Database (NVD) for potential CVE matches.

Extracts CVSS scores and assigns a risk level.

Generates a text report containing the scan results.

Example



A scan of a locally hosted Python HTTP server on port 8080 can produce output such as:



Port: 8080

Service: HTTP-Alt

Product: SimpleHTTP 0.6, Python 3.14.7

Vulnerabilities: (23)



CVE-2025-4517 | CVSS: 9.4 | Risk: Critical

CVE-2026-11816 | CVSS: 8.1 | Risk: High

...

Usage



Run the program from the project directory:



python netscan.py



The program will prompt for:



Target host:

Starting port:

Ending port:

Output filename:



For testing, NetScan can be used against a local service such as Python's built-in HTTP server:



python -m http.server 8080



Then scan 127.0.0.1 and port 8080 with NetScan.



Example Test Environment



The scanner was tested against a locally hosted Python HTTP server. This provided a controlled environment for testing:



Port discovery

HTTP service detection

Banner/version extraction

CVE lookup

Report generation

Known Limitations



The current CVE matching implementation uses keyword searches and version-string matching against NVD CVE descriptions. Because it does not yet use structured CPE data and affected-version ranges, the results may contain false positives.



For example, finding a version number in a CVE description does not necessarily mean that the detected software version is vulnerable.



A future version of NetScan could improve vulnerability accuracy by implementing:



CPE-based product identification

Structured affected-version matching

More reliable software fingerprinting

Additional service-specific version detection

More detailed report formats such as JSON or HTML

What I Learned



Building NetScan gave me hands-on experience with several cybersecurity and programming concepts, including:



TCP networking and socket programming

Concurrent network scanning

Service and software fingerprinting

HTTP request/response handling

Regular expression parsing

Working with REST APIs

CVE and CVSS concepts

Command-line application design

Vulnerability identification

Security tool development

Technical documentation

Disclaimer



NetScan is intended for educational purposes and authorized security testing only.



Only scan systems that you own or have explicit permission to test.

