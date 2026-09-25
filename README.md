
# 🔎 NetScan

**NetScan** is a Python-based network vulnerability scanner designed for **authorized security testing and cybersecurity education**.

It scans TCP ports, identifies common services, fingerprints HTTP software versions, queries the **NIST National Vulnerability Database (NVD)** for potential CVE matches, and generates a vulnerability report.

---

## 🚀 Features

* ⚡ Concurrent TCP port scanning with `ThreadPoolExecutor`
* 🔌 Common service identification based on port numbers
* 📡 TCP banner grabbing
* 🌐 HTTP service probing
* 🧾 HTTP `Server` header extraction
* 🔍 Software and version fingerprinting using regular expressions
* 🛡️ NVD CVE lookup
* 📊 CVSS score extraction and risk classification
* 📝 Automated text-based vulnerability reports
* 💻 Interactive command-line interface
* 🔐 Authorization confirmation before scanning

---

## 🛠️ Technologies

| Technology              | Purpose                             |
| ----------------------- | ----------------------------------- |
| **Python**              | Core programming language           |
| **Socket**              | TCP networking and port scanning    |
| **ThreadPoolExecutor**  | Concurrent port scanning            |
| **Regular Expressions** | Software/version detection          |
| **Requests**            | HTTP requests and API communication |
| **NVD API**             | CVE vulnerability information       |

---

## ⚙️ How It Works

NetScan follows a multi-stage scanning process:

```text
Target Host
     │
     ▼
Authorization Check
     │
     ▼
Concurrent Port Scan
     │
     ▼
Open Port Detection
     │
     ▼
Service Identification
     │
     ▼
Banner / HTTP Detection
     │
     ▼
Software & Version Fingerprinting
     │
     ▼
NVD CVE Lookup
     │
     ▼
CVSS Risk Classification
     │
     ▼
Vulnerability Report
```

### Scanning Process

1. Prompts the user for a target host and port range.
2. Confirms that the user has permission to scan the target.
3. Scans the specified ports concurrently.
4. Identifies open ports and maps common ports to associated services.
5. Attempts to grab service banners from open ports.
6. Probes HTTP services and extracts the `Server` header.
7. Identifies software products and versions from HTTP responses.
8. Queries the NVD for **potential CVE matches**.
9. Extracts CVSS scores and assigns a risk level.
10. Generates a text report containing the scan results.

---

## 💻 Usage

Run NetScan from the project directory:

```bash
python netscan.py
```

The program will prompt for:

```text
Target host:
Starting port:
Ending port:
Output filename:
```

### Example

```text
Target host: 127.0.0.1
Starting port: 1
Ending port: 1024
Output filename: report.txt
```

---

## 🧪 Example Test Environment

For testing, NetScan can be used against a locally hosted Python HTTP server.

Start the server:

```bash
python -m http.server 8080
```

Then run NetScan and scan:

```text
127.0.0.1
```

on port:

```text
8080
```

This provides a controlled environment for testing:

* Port discovery
* HTTP service detection
* Banner and version extraction
* CVE lookup
* CVSS risk classification
* Report generation

---

## 📄 Example Output

A scan of a locally hosted Python HTTP server can produce output similar to:

```text
Port: 8080
Service: HTTP-Alt
Product: SimpleHTTP 0.6, Python 3.14.7
Vulnerabilities: (23)

CVE-2025-4517 | CVSS: 9.4 | Risk: Critical
CVE-2026-11816 | CVSS: 8.1 | Risk: High
...
```

> **Note:** The CVEs shown above represent potential matches produced by the scanner's current matching logic. They should not be interpreted as confirmed vulnerabilities.

---

## ⚠️ Known Limitations

The current CVE matching implementation uses **keyword searches and version-string matching against NVD CVE descriptions**.

Because the scanner does not yet use structured **CPE data** or affected-version ranges, CVE results may contain false positives.

For example, finding a version number mentioned in a CVE description does **not necessarily mean that the detected software version is vulnerable**.

### Planned Improvements

Future versions of NetScan could improve vulnerability accuracy by implementing:

* CPE-based product identification
* Structured affected-version matching
* More reliable software fingerprinting
* Additional service-specific version detection
* JSON report generation
* HTML report generation
* More detailed vulnerability reporting

---

## 📚 What I Learned

Building NetScan provided hands-on experience with both cybersecurity and software development concepts, including:

### Networking

* TCP networking
* Socket programming
* Port scanning
* Service identification
* Banner grabbing

### Cybersecurity

* Service and software fingerprinting
* Vulnerability identification
* CVE and CVSS c
