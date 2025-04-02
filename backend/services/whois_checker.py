import whois
import socket
import ipaddress
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor


def is_ip(ip):
    """Check if the given string is a valid IP address."""
    try:
        return bool(ipaddress.ip_address(ip))
    except ValueError:
        return False


def is_url(url):
    """Check if the given string is a valid URL (must include a scheme)."""
    parsed = urlparse(url)
    return bool(parsed.scheme and parsed.netloc)


def is_domain(domain):
    """Check if the given string is a valid domain name."""
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def extract_domain(entry):
    """Extract the domain name from a URL or return the input if it's already a domain."""
    parsed = urlparse(entry)
    return parsed.netloc if parsed.netloc else entry


def clean_whois_data(data):
    """Filter and clean WHOIS data, keeping only relevant OSINT information."""

    def get_first(value):
        return value[0] if isinstance(value, list) and value else value or "Not available"

    return {
        "domain_name": get_first(data.get("domain_name")),
        "registrar": get_first(data.get("registrar")),
        "whois_server": get_first(data.get("whois_server")),
        "creation_date": get_first(data.get("creation_date")),
        "expiration_date": get_first(data.get("expiration_date")),
        "updated_date": get_first(data.get("updated_date")),
        "name_servers": data.get("name_servers", "Not available"),
        "status": data.get("status", "Not available"),
        "emails": get_first(data.get("emails")),
        "organization": get_first(data.get("org")),
        "address": get_first(data.get("address")),
        "city": get_first(data.get("city")),
        "state": get_first(data.get("state")),
        "country": get_first(data.get("country")),
    }


def whois_check(arg):
    """Perform a WHOIS lookup on a valid domain or IP address."""
    if not is_domain(arg) and not is_ip(arg):
        return {"error": "Invalid argument."}
    try:
        target = extract_domain(arg)
        whois_data = whois.whois(target)
        return clean_whois_data(whois_data)
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}


def scan_http_headers(url):
    """Retrieve HTTP headers from the target URL."""
    try:
        response = requests.get(url, timeout=5)
        return response.headers
    except requests.RequestException as e:
        return {"error": f"HTTP request failed: {e}"}


def scan_subdomains(domain_name, subdomains):
    """Scan for active subdomains in parallel."""

    def check_subdomain(subdomain):
        url = f"https://{subdomain}.{domain_name}"
        try:
            requests.get(url, timeout=3)
            return url
        except requests.ConnectionError:
            return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(filter(None, executor.map(check_subdomain, subdomains)))
    return results


def fetch_subdomains_crt(domain):
    """Retrieve subdomains from crt.sh"""
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return list(set(entry['name_value'] for entry in data))
    except requests.RequestException as e:
        return {"error": f"crt.sh request failed: {e}"}
    return []


def main(target):
    """Run the full OSINT scan on a target domain."""
    print(f"[+] Scanning {target}...")

    whois_info = whois_check(target)
    headers_info = scan_http_headers(f"https://{target}")
    crt_subdomains = fetch_subdomains_crt(target)

    subdomains_to_check = ["www", "mail", "ftp", "blog", "admin", "secure", "test"] + crt_subdomains
    active_subdomains = scan_subdomains(target, subdomains_to_check)

    report = {
        "WHOIS": whois_info,
        "HTTP Headers": headers_info,
        "Subdomains": active_subdomains,
    }

    print(report)
    return report


if __name__ == "__main__":
    domain_input = input("Enter domain: ")
    main(domain_input)


