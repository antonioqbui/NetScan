import socket
import requests
import re

from constants import COMMON_PORTS

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

def extract_product_versions(server_value: str) -> list:
        return re.findall(r"([A-Za-z][A-Za-z0-9_-]*)/(\d+(?:\.\d+)*)", server_value)

