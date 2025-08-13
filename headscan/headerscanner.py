from pywebio.input import input, input_group
from pywebio.output import (
    put_text, put_markdown, put_table, put_warning,
    put_success, put_code, put_button
)
from pywebio import start_server
from pywebio.session import run_js
from pywebio.output import use_scope
import requests
import shodan
from urllib.parse import urlparse
import socket

SHODAN_API_KEY = ''
shodan_api = shodan.Shodan(SHODAN_API_KEY)

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS",
    "Content-Security-Policy": "Prevents XSS and data injection",
    "X-Frame-Options": "Clickjacking protection",
    "X-Content-Type-Options": "MIME sniffing prevention",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Restricts browser features",
    "Access-Control-Allow-Origin": "CORS policy",
    "Expect-CT": "Certificate transparency enforcement",
    "Cache-Control": "Controls caching behavior",
}

COMMON_METHODS = ["GET", "POST", "OPTIONS", "HEAD", "PUT", "DELETE", "PATCH"]

def check_http_methods(url):
    try:
        response = requests.options(url, timeout=10)
        allowed = response.headers.get("Allow", "Unknown")
        return allowed
    except:
        return "Unable to determine"

def get_redirect_chain(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        chain = [resp.url for resp in response.history] + [response.url]
        return chain
    except:
        return []

def check_ssl(url):
    parsed = urlparse(url)
    return parsed.scheme == "https"

def get_ip_address(domain):
    try:
        # Remove http:// or https:// if present
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except Exception as e:
        return f"Could not resolve IP: {str(e)}"

def scan_security_headers():
    with use_scope('result', clear=True):
        put_markdown("## 🔐 Tabs Security Header & Web Scanner")

        user_input = input_group("Enter Target Domain", [
            input("Domain (e.g. https://example.com)", name='domain')
        ])
        url = user_input['domain'].strip()

        put_markdown(f"### 🌐 Target: `{url}`")

     
        ip_address = get_ip_address(url)
        put_markdown(f"### 📡 IP Address: `{ip_address}`")

        try:
            response = requests.get(url, timeout=10)
            headers = response.headers

            # --- HEADER SCANNING ---
            found = []
            missing = []

            for header, description in SECURITY_HEADERS.items():
                if header in headers:
                    found.append([header, headers[header]])
                else:
                    missing.append([header, description])

            if found:
                put_success("✅ Found Security Headers")
                put_table([["Header", "Value"]] + found)
            else:
                put_warning("No security headers found!")

            if missing:
                put_warning("❌ Missing Security Headers")
                put_table([["Header", "Purpose"]] + missing)
            else:
                put_success("All recommended headers are present!")

        
            put_markdown("### 🔍 Allowed HTTP Methods")
            methods = check_http_methods(url)
            put_text(f"Allowed Methods: {methods}")

         
            put_markdown("### 🔐 SSL/TLS Check")
            if check_ssl(url):
                put_success("Site uses HTTPS")
            else:
                put_warning("Site does not enforce HTTPS")

         
            put_markdown("### 🔁 Redirect Chain")
            chain = get_redirect_chain(url)
            if len(chain) > 1:
                put_table([["Step", "URL"]] + [[str(i+1), step] for i, step in enumerate(chain)])
            else:
                put_text("No redirection detected.")

           
            put_markdown("### 🧬 Server Fingerprinting")
            server = headers.get("Server", "Not disclosed")
            powered_by = headers.get("X-Powered-By", "Not disclosed")
            put_table([
                ["Header", "Value"],
                ["Server", server],
                ["X-Powered-By", powered_by]
            ])


            put_markdown("### 🌐 CORS Policy")
            cors = headers.get("Access-Control-Allow-Origin", "Missing")
            if cors == "*":
                put_warning("CORS is too permissive (Access-Control-Allow-Origin: *)")
            else:
                put_text(f"Access-Control-Allow-Origin: {cors}")

            # --- Content-Security-Policy (Weakness Check) ---
            put_markdown("### 🧪 Content-Security-Policy Evaluation")
            csp = headers.get("Content-Security-Policy")
            if not csp:
                put_warning("Missing Content-Security-Policy header")
            elif "'unsafe-inline'" in csp or "*" in csp:
                put_warning("⚠️ CSP may be weak (contains '*' or 'unsafe-inline')")
                put_code(csp, language="html")
            else:
                put_success("CSP seems strong")
                put_code(csp, language="html")

        
            ip = urlparse(url).hostname
            put_markdown("### 🕵️ Shodan Host Info")

            try:
                shodan_results = shodan_api.search(f'hostname:{ip}')
                if shodan_results['matches']:
                    first = shodan_results['matches'][0]
                    put_table([
                        ["Field", "Value"],
                        ["IP", first.get("ip_str", "n/a")],
                        ["Org", first.get("org", "n/a")],
                        ["Port", first.get("port", "n/a")],
                        ["Banner Snippet", first.get("data", "").split("\n")[0]],
                    ])
                else:
                    put_text("No public Shodan data found for this host.")
            except Exception as e:
                put_warning(f"Shodan lookup failed: {e}")


            put_button("🔁 Scan Another", onclick=lambda: run_js('window.location.reload()'), color='primary')

        except requests.exceptions.RequestException as e:
            put_warning(f"Scan error: {str(e)}")
            put_button("Try Again", onclick=lambda: run_js('window.location.reload()'), color='danger')


if __name__ == '__main__':
    start_server(scan_security_headers, port=8080, debug=True)
