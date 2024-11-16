import socket
import ssl
import time
import requests
from colorama import Fore, init
from bs4 import BeautifulSoup
import dns.resolver

init(autoreset=True)

log_file = "log.txt"

def write_log(message):
    with open(log_file, "a") as log:
        log.write(message + "\n")

def resolve_ip(host):
    try:
        ip = socket.gethostbyname(host)
        message = f"[✔] Resolved IP Address: {ip}"
        print(Fore.GREEN + message)
        write_log(message)
        return ip
    except socket.gaierror as e:
        error_message = f"[✘] Failed to resolve IP: {str(e)}"
        print(Fore.RED + error_message)
        write_log(error_message)
        return None

def perform_dns_lookup(host):
    try:
        records = dns.resolver.resolve(host, 'A')
        ips = [r.address for r in records]
        message = f"[✔] DNS A Records: {', '.join(ips)}"
        print(Fore.GREEN + message)
        write_log(message)
    except Exception as e:
        error_message = f"[✘] DNS Lookup Failed: {str(e)}"
        print(Fore.RED + error_message)
        write_log(error_message)

def fetch_ssl_certificate(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                issuer = cert.get('issuer', [])
                issued_to = cert.get('subject', [])
                validity = cert.get('notAfter')
                message = (
                    f"[✔] SSL Certificate Details:\n"
                    f"    Issued To: {issued_to}\n"
                    f"    Issuer: {issuer}\n"
                    f"    Valid Until: {validity}"
                )
                print(Fore.CYAN + message)
                write_log(message)
    except Exception as e:
        error_message = f"[✘] SSL Certificate Fetch Failed: {str(e)}"
        print(Fore.RED + error_message)
        write_log(error_message)

def fetch_website_metadata(url):
    try:
        response = requests.get(url, timeout=5)
        content_length = len(response.content)
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string if soup.title else "N/A"
        meta_description = (
            soup.find("meta", attrs={"name": "description"})
            or soup.find("meta", attrs={"property": "og:description"})
        )
        meta_description = meta_description["content"] if meta_description else "N/A"

        message = (
            f"[✔] Website Metadata:\n"
            f"    Title: {title}\n"
            f"    Meta Description: {meta_description}\n"
            f"    Content Length: {content_length} bytes"
        )
        print(Fore.CYAN + message)
        write_log(message)
    except Exception as e:
        error_message = f"[✘] Failed to fetch website metadata: {str(e)}"
        print(Fore.RED + error_message)
        write_log(error_message)

def test_sni_connection(sni_host):
    ip = resolve_ip(sni_host)
    if ip:
        perform_dns_lookup(sni_host)
        fetch_ssl_certificate(sni_host)
    test_https_request(sni_host)
    fetch_website_metadata(f"https://{sni_host}")

def test_https_request(host):
    try:
        response = requests.get(f'https://{host}', timeout=5)
        log_http_headers(response)
    except requests.exceptions.RequestException as e:
        error_message = f"[✘] HTTPS GET request failed: {str(e)}"
        print(Fore.RED + error_message)
        write_log(error_message)

def log_http_headers(response):
    log = []
    log.append(f"[0] => {response.request.method} {response.url}")
    for i, (key, value) in enumerate(response.request.headers.items(), start=1):
        log.append(f"[{i}] => {key}: {value}")
    
    log.append(f"[0] => HTTP/{response.raw.version} {response.status_code} {response.reason}")
    for i, (key, value) in enumerate(response.headers.items(), start=1):
        log.append(f"[{i}] => {key}: {value}")
    
    log_content = "\n".join(log)
    print(log_content)
    write_log(log_content)

def print_banner():
    banner = "=== Enhanced SNI Connection Tester ==="
    print(Fore.CYAN + banner)
    write_log(banner)

def main():
    print_banner()
    sni_host = input(Fore.CYAN + "[+] Enter the SNI host (URL without https://): ")
    print(Fore.YELLOW + "\n[~] Initiating enhanced connection test...\n")
    write_log(f"[~] Initiating connection test for host: {sni_host}")
    test_sni_connection(sni_host)

if __name__ == "__main__":
    with open(log_file, "w") as log:
        log.write("=== Log Start ===\n")
    main()
