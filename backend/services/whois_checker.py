import whois
import socket
import ipaddress
import requests
import json
import os
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

VT_API_KEY = os.getenv("VT_API_KEY", "c2337922306e40e9c5701d839ec5a54e9480107b8fbfc90ead2969de62a7d3f3")


def is_ip(ip):
    try:
        return bool(ipaddress.ip_address(ip))
    except ValueError:
        return False


def is_domain(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False


def extract_domain(entry):
    parsed = urlparse(entry)
    return parsed.netloc if parsed.netloc else entry


def clean_whois_data(data):
    def get_first(value):
        if isinstance(value, list) and value:
            value = value[0]
        if isinstance(value, datetime):
            return value.strftime("%Y-%m-%d %H:%M:%S")
        return value or "Not available"

    return {
        "domain_name": get_first(data.get("domain_name")),
        "registrar": get_first(data.get("registrar")),
        "creation_date": get_first(data.get("creation_date")),
        "expiration_date": get_first(data.get("expiration_date")),
        "emails": get_first(data.get("emails")),
        "organization": get_first(data.get("org")),
        "country": get_first(data.get("country")),
    }


def whois_check(arg):
    if not is_domain(arg):
        return {"error": "Invalid domain."}
    try:
        target = extract_domain(arg)
        whois_data = whois.whois(target)
        return clean_whois_data(whois_data)
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}


def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        data = response.json()

        if response.status_code == 200:
            last_analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "harmless": last_analysis_stats.get("harmless", 0),
                "malicious": last_analysis_stats.get("malicious", 0),
                "suspicious": last_analysis_stats.get("suspicious", 0),
                "undetected": last_analysis_stats.get("undetected", 0),
            }
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except requests.RequestException as e:
        return {"error": f"Request failed: {e}"}


def scan_http_headers(url):
    try:
        response = requests.get(url, timeout=5)
        return dict(response.headers)  # Convert CaseInsensitiveDict to a normal dict
    except requests.RequestException as e:
        return {"error": f"HTTP request failed: {e}"}


def load_subdomains(file_path="../files/subdomainslist.txt"):
    if not os.path.exists(file_path):
        print(f"[-] Warning: Subdomain file {file_path} not found.")
        return []
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file.readlines()]
    except Exception as e:
        print(f"[-] Error reading subdomains file: {e}")
        return []


def scan_subdomains(domain_name, subdomains):
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
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return list(set(entry.get('name_value', '') for entry in data if 'name_value' in entry))
    except requests.RequestException:
        print("[-] Failed to retrieve subdomains from crt.sh")
        return []
    return []


def save_results_to_json(target, data):
    filename = f"{target}_osint_results.json"
    try:
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
        print(f"[+] Report saved as {filename}")
    except IOError as e:
        print(f"[-] Failed to save JSON file: {e}")


def main(target):
    print(f"[+] Scanning {target}...")

    whois_info = whois_check(target)
    headers_info = scan_http_headers(f"https://{target}")
    crt_subdomains = fetch_subdomains_crt(target)
    vt_info = check_virustotal(target)

    subdomain_file = "../files/subdomainslist.txt"
    subdomains_from_file = load_subdomains(subdomain_file)
    subdomains_to_check = list(set(subdomains_from_file + crt_subdomains))

    active_subdomains = scan_subdomains(target, subdomains_to_check)

    report = {
        "WHOIS": whois_info,
        "VirusTotal": vt_info,
        "HTTP Headers": headers_info,
        "Subdomains": active_subdomains,
    }

    save_results_to_json(target, report)


if __name__ == "__main__":
    domain_input = input("Enter domain: ")
    main(domain_input)





