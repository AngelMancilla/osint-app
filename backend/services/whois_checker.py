import whois
import socket
import ipaddress
from urllib.parse import urlparse

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

def valid_arg(arg):
    """Determine if the input is a valid IP, URL, or domain."""
    return is_ip(arg) or is_url(arg) or is_domain(arg)

def extract_domain(entry):
    """Extract the domain name from a URL or return the input if it's already a domain."""
    parsed = urlparse(entry)
    return parsed.netloc if parsed.netloc else entry  # Handles both URLs and direct domains

def clean_whois_data(data):
    """Filter and clean WHOIS data, keeping only relevant OSINT information."""
    def get_first(value):
        """Extract the first element if the value is a list, otherwise return it directly."""
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
    if not valid_arg(arg):
        raise ValueError("Invalid argument.")

    try:
        target = extract_domain(arg)
        print(f"Extracted domain: {target}") if is_url(arg) else None

        whois_data = whois.whois(target)
        return clean_whois_data(whois_data)

    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

# Test cases
if __name__ == "__main__":
    test_cases = [
        "192.168.1.1",  # Private IP (expected limited WHOIS data)
        "8.8.8.8",  # Public IP (Google DNS)
        "https://www.google.com",  # URL (should extract "google.com")
        "google.com",  # Domain
        "256.256.256.256",  # Invalid IP (should raise an error)
        "invalid_url",  # Invalid URL (should raise an error)
    ]

    for test in test_cases:
        try:
            print(f"Checking {test}:")
            result = whois_check(test)
            print(result)
        except ValueError as e:
            print(f"Error: {e}")
        print("-" * 50)
