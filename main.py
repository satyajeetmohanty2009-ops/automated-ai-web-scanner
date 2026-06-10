import json
import random
import re
import os
import ssl
import socket
import sqlite3
import time
from datetime import datetime
from pathlib import Path
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from bs4 import BeautifulSoup
# Google GenAI SDK (Modern standard for Gemini)
from google import genai
from google.genai import types

# Define extraction regex rules to strip away boilerplate JS
SENSITIVE_PATHS = [
    "/admin/", "/backup/", "/.git/", "/.env", "/config.json", "/config.php", "/db/", "/dump.sql",
    "/.ssh/", "/.well-known/", "/robots.txt", "/.htaccess", "/wp-admin/", "/api/docs/",
]

SUBDOMAIN_WORDS = [
    "admin", "dev", "staging", "test", "api", "mail", "portal", "auth", "secure", "docs",
    "beta", "webmail", "dashboard", "support", "shop", "cdn", "login", "cdn", "static",
]

SECURITY_HEADER_LIST = [
    "content-security-policy",
    "x-frame-options",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6425.181 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.37 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/127.0.908.100 Safari/537.36",
]

VULNERABILITY_PATTERNS = {
    "Potential Credentials": r'(?i)(password|passwd|master_key|secret|credential|privkey|client_secret|access_token|secret_key)\s*[:=]\s*["\']([^"\']+)["\']',
    "API Keys & Cloud Tokens": r'(?i)(aws_key|api_key|service_account|bearer|jwt|token|stripe_.*|sk_live_.*|sk_test_.*|sg\.[A-Za-z0-9_-]{16,}|EAACEdEose0cBA[0-9A-Za-z]+)\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
    "Authentication Tokens": r'(?i)(xoxb-[0-9A-Za-z\-]{10,}|xoxp-[0-9A-Za-z\-]{10,}|raven|jwt|eyJ[0-9A-Za-z_-]{10,})',
    "Endpoints & Internal Routes": r'["\'](\/[-a-zA-Z0-9_@:%_\+.~#?&/=]+|\S+\.amazonaws\.com\S*|\S+\.blob\.core\.windows\.net\S*|\S+\.storage\.googleapis\.com\S*)["\']',
}

JS_SIGNAL_PATTERNS = {
    "DOM XSS Sinks": r'(?i)(eval\(|document\.write\(|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML\(|setAttribute\(\s*["\'](src|href|data|action)["\'])',
    "Third-Party Libraries": r'(?i)(jquery[-\.][0-9]+|angular[-\.][0-9]+|vue[-\.][0-9]+|bootstrap[-\.][0-9]+|react[-\.][0-9]+|ember[-\.][0-9]+)',
    "Comment & Debug Metadata": r'(?i)(TODO|FIXME|DEBUG|NOTE|console\.log\(|console\.debug\(|\/\*.*?\*\/|\/\/.*$)',
    "Cloud Storage Signatures": r'(?i)(s3:\/\/|gs:\/\/|blob:\/\/|\.s3\.amazonaws\.com|\.storage\.googleapis\.com|\.blob\.core\.windows\.net|\.digitaloceanspaces\.com)',
}

HTML_SIGNAL_PATTERNS = {
    "Forms & Inputs": r'(?i)<form[^>]*>|<input[^>]*>|<textarea[^>]*>|<button[^>]*>|<select[^>]*>',
    "Meta & Public Keys": r'(?i)<meta[^>]+>|<link[^>]+>|<script[^>]+>|<style[^>]+>',
    "Insecure Form Actions": r'(?i)<form[^>]+action\s*=\s*["\']http:\/\/',
    "Mixed Content Assets": r'(?i)<(script|img|link|iframe)[^>]+src\s*=\s*["\']http:\/\/',
}

JS_LIBRARY_VERSION_PATTERNS = {
    "jQuery Version": r'(?i)jquery(?:\.min)?\.js(?:\?ver=|\-)([0-9]+\.[0-9]+\.[0-9]+)',
    "Angular Version": r'(?i)angular(?:\.min)?\.js(?:\?ver=|\-)([0-9]+\.[0-9]+\.[0-9]+)',
    "Vue Version": r'(?i)vue(?:\.min)?\.js(?:\?ver=|\-)([0-9]+\.[0-9]+\.[0-9]+)',
    "React Version": r'(?i)react(?:\.min)?\.js(?:\?ver=|\-)([0-9]+\.[0-9]+\.[0-9]+)',
}

URL_PARAMETER_RISK_PATTERNS = {
    "Suspicious Query Parameters": r'(?i)([\?&](redirect|next|url|return|continue|callback|token|session|auth|state)=)',
}

TOKEN_PATTERNS = {
    "Slack Webhook": r'(?i)https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/]+',
    "Stripe Key": r'(?i)sk_(live|test)_[0-9A-Za-z]{24,}',
    "Mailgun API Key": r'(?i)key-[0-9A-Za-z]{32}',
    "JWT": r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
}

FINDING_CATEGORY_RISK_MAP = {
    "Potential Credentials": "Secret or credential exposure",
    "API Keys & Cloud Tokens": "API key leakage or cloud credential disclosure",
    "Authentication Tokens": "Session/token theft or credential reuse risk",
    "Endpoints & Internal Routes": "Internal endpoint exposure or protected route leakage",
    "DOM XSS Sinks": "Potential DOM-based cross-site scripting",
    "Third-Party Libraries": "Outdated or vulnerable third-party dependencies",
    "Comment & Debug Metadata": "Information leakage from comments or debug artifacts",
    "Cloud Storage Signatures": "Public cloud storage or object exposure",
    "Slack Webhook": "Potential secret webhook exposure",
    "Stripe Key": "Payment credential disclosure",
    "Mailgun API Key": "Email provider credential leakage",
    "JWT": "Token exposure leading to authentication bypass",
    "Forms & Inputs": "Potential form injection or insecure user input handling",
    "Meta & Public Keys": "Public metadata or configuration exposure",
    "Deep Directory Probes": "Exposed sensitive directories or forgotten assets",
    "Subdomain Candidates": "Secondary surface area that may host weaker software",
    "Security Headers": "Missing HTTP security headers",
    "Suspicious Query Parameters": "Potential open redirect, SSRF, or authentication bypass risk",
    "TLS Info": "Weak or outdated TLS configuration",
}

def extract_content_signals(content, source_label):
    findings = {}
    normalized_content = content if isinstance(content, str) else str(content)

    for category, pattern in VULNERABILITY_PATTERNS.items():
        matches = re.findall(pattern, normalized_content)
        unique_matches = list({m if isinstance(m, str) else m[0] for m in matches})
        if unique_matches:
            findings[category] = unique_matches[:20]

    for category, pattern in JS_SIGNAL_PATTERNS.items():
        matches = re.findall(pattern, normalized_content)
        unique_matches = list({str(m) for m in matches})
        if unique_matches:
            findings[category] = unique_matches[:20]

    for category, pattern in HTML_SIGNAL_PATTERNS.items():
        matches = re.findall(pattern, normalized_content)
        unique_matches = list({str(m) for m in matches})
        if unique_matches:
            findings[category] = unique_matches[:20]

    for category, pattern in JS_LIBRARY_VERSION_PATTERNS.items():
        matches = re.findall(pattern, normalized_content)
        if matches:
            findings[category] = list(set(matches))[:10]

    for category, pattern in URL_PARAMETER_RISK_PATTERNS.items():
        matches = re.findall(pattern, normalized_content)
        if matches:
            findings[category] = list(set(matches))[:20]

    for category, pattern in TOKEN_PATTERNS.items():
        matches = re.findall(pattern, normalized_content)
        if matches:
            findings[category] = list(set(matches))[:10]

    if findings:
        findings["Source"] = [source_label]

    return findings


def get_random_headers(overrides=None):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    }
    if overrides:
        headers.update(overrides)
    return headers


def get_request_delay(base_delay):
    if base_delay <= 0:
        return 0.0

    min_delay = max(0.1, base_delay * 0.4)
    max_delay = base_delay * 1.6 + 0.1
    jitter = random.uniform(min_delay, max_delay)
    return round(jitter, 2)


def parse_proxy_string(proxy_string):
    if not proxy_string:
        return {}
    proxy_url = proxy_string.strip()
    if not proxy_url.startswith("http") and not proxy_url.startswith("socks"):
        proxy_url = f"http://{proxy_url}"
    return {"http": proxy_url, "https": proxy_url}


class ScanStateDB:
    def __init__(self, path):
        self.path = Path(path)
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cur = self.conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS pages (
                url TEXT PRIMARY KEY,
                depth INTEGER,
                status TEXT,
                last_seen TEXT
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS queue (
                url TEXT PRIMARY KEY,
                depth INTEGER
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                category TEXT,
                item TEXT,
                source TEXT
            )
            """
        )
        self.conn.commit()

    def seed_url(self, url, depth=0):
        cur = self.conn.cursor()
        cur.execute("INSERT OR IGNORE INTO queue (url, depth) VALUES (?, ?)", (url, depth))
        self.conn.commit()

    def load_queue(self):
        cur = self.conn.cursor()
        cur.execute("SELECT url, depth FROM queue ORDER BY rowid")
        return [(row["url"], row["depth"]) for row in cur.fetchall()]

    def load_visited(self):
        cur = self.conn.cursor()
        cur.execute("SELECT url FROM pages WHERE status = 'done'")
        return {row["url"] for row in cur.fetchall()}

    def persist_queue(self, queue):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM queue")
        cur.executemany("INSERT OR IGNORE INTO queue (url, depth) VALUES (?, ?)", queue)
        self.conn.commit()

    def mark_page(self, url, depth=0, status="done"):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO pages (url, depth, status, last_seen) VALUES (?, ?, ?, ?)",
            (url, depth, status, datetime.utcnow().isoformat() + "Z"),
        )
        self.conn.commit()

    def add_finding(self, category, item, source="scanner"):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO findings (category, item, source) VALUES (?, ?, ?)", (category, item, source))
        self.conn.commit()

    def load_findings(self):
        cur = self.conn.cursor()
        cur.execute("SELECT category, item FROM findings")
        findings = {}
        for row in cur.fetchall():
            findings.setdefault(row["category"], []).append(row["item"])
        return findings


def safe_request(session, method, url, delay=0, **kwargs):
    headers = kwargs.pop("headers", None)
    headers = get_random_headers(headers)
    effective_delay = get_request_delay(delay)
    if effective_delay > 0:
        time.sleep(effective_delay)
    try:
        request_fn = getattr(session, method)
        response = request_fn(url, headers=headers, **kwargs)
        return response
    except (requests.RequestException, Exception):
        return None


def fetch_and_extract_js_live(js_url, session, delay=0):
    """Streams a single JS URL into memory and extracts patterns instantly."""
    response = safe_request(session, 'get', js_url, timeout=10, delay=delay, stream=True)
    if not response or response.status_code != 200:
        return {}

    findings = extract_content_signals(response.text, js_url)
    source_map_text = probe_js_source_map(js_url, session, delay=delay)
    if source_map_text:
        findings.setdefault("Discovered JS Source Maps", []).append(f"{js_url}.map")
        findings.update(extract_content_signals(source_map_text, js_url + ".map"))
    return findings


def query_osv_vulnerabilities(package_name, version):
    payload = {
        "version": version,
        "package": {
            "name": package_name,
            "ecosystem": "npm"
        }
    }
    try:
        resp = requests.post("https://api.osv.dev/v1/query", json=payload, timeout=10)
        if resp.ok:
            data = resp.json()
            vulns = []
            for vuln in data.get("vulns", []):
                vuln_id = vuln.get("id")
                summary = vuln.get("summary", "")
                if vuln_id:
                    vulns.append(f"{vuln_id}: {summary}".strip())
            return vulns
    except Exception:
        pass
    return []


def detect_library_version_vulnerabilities(content):
    packages = {
        "jQuery Version": "jquery",
        "Angular Version": "angular",
        "Vue Version": "vue",
        "React Version": "react",
    }
    findings = {}
    for category, pattern in JS_LIBRARY_VERSION_PATTERNS.items():
        matches = re.findall(pattern, content)
        for version in set(matches):
            package_name = packages.get(category, category.split()[0].lower())
            vuln_list = query_osv_vulnerabilities(package_name, version)
            if vuln_list:
                findings.setdefault("Dependency Vulnerabilities", []).append(
                    f"{category} {version} -> {', '.join(vuln_list)}"
                )
    return findings


def extract_source_map_url(js_text):
    match = re.search(r"sourceMappingURL=([^\s'\"]+)", js_text)
    if match:
        return match.group(1).strip()
    return None


def probe_js_source_map(js_url, session, delay=0):
    map_url = js_url + ".map"
    response = safe_request(session, 'get', map_url, timeout=10, delay=delay)
    if response and response.status_code == 200:
        return response.text

    response = safe_request(session, 'get', js_url, timeout=10, delay=delay, stream=True)
    if response and response.status_code == 200:
        inferred = extract_source_map_url(response.text)
        if inferred:
            inferred_url = urllib.parse.urljoin(js_url, inferred)
            response = safe_request(session, 'get', inferred_url, timeout=10, delay=delay)
            if response and response.status_code == 200:
                return response.text
    return None


def verify_dom_xss(page_url):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None

    payload = "<svg/onload=window.__dom_xss_test=1>"
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.evaluate_on_new_document("() => { window.__dom_xss_test = false; }")
            page.goto(page_url, timeout=15000)
            page.evaluate(f"() => {{ window.__injected = '{payload}'; }}")
            result = page.evaluate("() => window.__dom_xss_test")
            browser.close()
            if result:
                return f"DOM XSS payload appeared to execute on {page_url}"
    except Exception:
        return None
    return None


def split_into_chunks(text, max_chars=12000):
    lines = text.splitlines()
    chunks = []
    current = []
    current_len = 0
    for line in lines:
        if current_len + len(line) + 1 > max_chars and current:
            chunks.append("\n".join(current))
            current = []
            current_len = 0
        current.append(line)
        current_len += len(line) + 1
    if current:
        chunks.append("\n".join(current))
    return chunks


def load_security_reference_context():
    context = []
    references_dir = Path("references")
    for file_name in ["owasp.json", "cwe.json"]:
        file_path = references_dir / file_name
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8") as stream:
                    data = json.load(stream)
                    context.append(f"Loaded {file_name} definitions: {len(data)} entries.")
            except Exception:
                pass
    return "\n".join(context)


def build_finder_prompt(findings, reference_context=""):
    prompt = (
        "You are The Finder: Identify only credible vulnerability signals from the following reconnaissance output. "
        "Do not hallucinate. Flag only issues with strong evidence.\n\n"
    )
    if reference_context:
        prompt += f"Security reference context:\n{reference_context}\n\n"
    prompt += "Reconnaissance data:\n"
    for category, items in findings.items():
        prompt += f"### {category}\n"
        for item in items[:30]:
            prompt += f"- {item}\n"
    prompt += "\nProvide brief findings and the evidence for each one."
    return prompt


def build_critic_prompt(finder_result, reference_context=""):
    prompt = (
        "You are The Critic: Review the candidate findings below and attempt to disprove them. "
        "If the evidence does not support a finding, label it as low-confidence or discard it."
    )
    if reference_context:
        prompt += f"\nSecurity reference context:\n{reference_context}\n"
    prompt += f"\n\nCandidate findings:\n{finder_result}\n\n"
    prompt += "For each finding, decide whether it is high-confidence, medium-confidence, or unsupported. Return only the validated, high-confidence issues."
    return prompt


def run_ai_prompt(prompt_text, system_instruction, gemini_api_key=None):
    if gemini_api_key:
        try:
            client = genai.Client(api_key=gemini_api_key)
            response_stream = client.models.generate_content_stream(
                model='gemini-2.5-flash',
                contents=prompt_text,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    temperature=0.1,
                )
            )
            output = []
            for chunk in response_stream:
                output.append(chunk.text)
            return "".join(output)
        except Exception:
            pass

    try:
        local_payload = {
            "model": "llama3",
            "prompt": f"{system_instruction}\n\n{prompt_text}",
            "stream": False,
        }
        res = requests.post("http://localhost:11434/api/generate", json=local_payload, timeout=30)
        if res.ok:
            return res.text
    except Exception:
        pass

    return "[AI unavailable]"


def query_ai_engine(recon_data, findings):
    """Pipes data through a two-tier AI verification pipeline."""
    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    reference_context = load_security_reference_context()

    finder_system = (
        "You are The Finder: a strict, cynical penetration testing assistant. "
        "Identify only high-confidence vulnerabilities from the reconnaissance output. "
        "If the evidence is incomplete, do not infer a vulnerability."
    )

    critic_system = (
        "You are The Critic: a senior security auditor. "
        "Review the candidate findings and discard anything that cannot be justified by strong evidence."
    )

    prompt_1 = build_finder_prompt(findings, reference_context)
    print("\n=== AI FINDER PASS ===\n")
    finder_output = run_ai_prompt(prompt_1, finder_system, gemini_api_key=gemini_api_key)
    print(finder_output)

    print("\n=== AI CRITIC PASS ===\n")
    prompt_2 = build_critic_prompt(finder_output, reference_context)
    critic_output = run_ai_prompt(prompt_2, critic_system, gemini_api_key=gemini_api_key)
    print(critic_output)
    return critic_output
    if not href or href.startswith("javascript:") or href.startswith("mailto:"):
        return None

    try:
        joined = urllib.parse.urljoin(base_url, href.split('#')[0])
        parsed = urllib.parse.urlparse(joined)
        if not parsed.scheme.startswith("http"):
            return None
        return joined
    except Exception:
        return None


def extract_query_parameter_signals(url):
    parsed = urllib.parse.urlparse(url)
    if not parsed.query:
        return []

    params = urllib.parse.parse_qs(parsed.query)
    suspicious = []
    risk_keys = {"redirect", "next", "url", "return", "continue", "callback", "token", "session", "auth", "state", "returnTo"}
    for key, value in params.items():
        if key.lower() in risk_keys:
            suspicious.append(f"{url} -> {key}={value}")
    return suspicious


def crawl_internal_links(base_url, session, max_depth=2, max_pages=200, workers=20, delay=0, state_store=None):
    parsed_base = urllib.parse.urlparse(base_url)
    base_netloc = parsed_base.netloc.lower()

    if state_store:
        queue = state_store.load_queue()
        visited = state_store.load_visited()
        if not queue:
            queue = [(base_url, 0)]
            state_store.seed_url(base_url, 0)
        queued = {url for url, _ in queue}
    else:
        queue = [(base_url, 0)]
        visited = set()
        queued = {base_url}

    page_records = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        while queue and len(page_records) < max_pages:
            batch = []
            while queue and len(batch) < workers and len(page_records) + len(batch) < max_pages:
                batch.append(queue.pop(0))

            futures = {
                executor.submit(safe_request, session, 'get', url, timeout=10, delay=delay): (url, depth)
                for url, depth in batch
            }

            for future in as_completed(futures):
                url, depth = futures[future]
                res = future.result()
                if not res:
                    continue

                content_type = res.headers.get('Content-Type', '')
                if 'html' not in content_type.lower():
                    continue

                soup = BeautifulSoup(res.text, 'html.parser')
                page_records.append((url, res.text, soup))
                visited.add(url)
                if state_store:
                    state_store.mark_page(url, depth, status='done')

                if len(page_records) >= max_pages:
                    break

                for anchor in soup.find_all('a', href=True):
                    next_url = normalize_internal_link(anchor['href'], url)
                    if not next_url or next_url in queued or next_url in visited:
                        continue

                    parsed_next = urllib.parse.urlparse(next_url)
                    if parsed_next.netloc.lower() == base_netloc and depth + 1 <= max_depth:
                        queued.add(next_url)
                        queue.append((next_url, depth + 1))

            if state_store:
                state_store.persist_queue(queue)

            if len(page_records) >= max_pages:
                break

    return queued, page_records


def probe_deep_directories(base_url, session, delay=0):
    found = []
    for path in SENSITIVE_PATHS:
        url = urllib.parse.urljoin(base_url, path)
        res = safe_request(session, 'head', url, allow_redirects=True, timeout=7, delay=delay)
        if not res:
            res = safe_request(session, 'get', url, allow_redirects=True, timeout=7, delay=delay)
        if res and res.status_code < 400:
            found.append(f"{url} ({res.status_code})")
    return found


def probe_subdomains(base_url, session, delay=0):
    parsed = urllib.parse.urlparse(base_url)
    scheme = parsed.scheme or 'https'
    domain = parsed.netloc.split(':')[0]
    found = []

    for token in SUBDOMAIN_WORDS:
        candidate = f"{scheme}://{token}.{domain}"
        res = safe_request(session, 'head', candidate, allow_redirects=True, timeout=7, delay=delay)
        if not res:
            res = safe_request(session, 'get', candidate, allow_redirects=True, timeout=7, delay=delay)
        if res and res.status_code < 400:
            found.append(f"{candidate} ({res.status_code})")

    return found


def get_security_headers(base_url, session, delay=0):
    status = {}
    res = safe_request(session, 'get', base_url, timeout=10, delay=delay)
    if not res:
        status["error"] = f"Unable to fetch header data for {base_url}"
        return status

    for header in SECURITY_HEADER_LIST:
        status[header] = res.headers.get(header, "MISSING")
    status["server"] = res.headers.get("Server", "UNKNOWN")
    status["status_code"] = str(res.status_code)
    return status


def get_tls_info(base_url):
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme != 'https' or not parsed.hostname:
        return {"tls_version": "N/A"}

    try:
        port = parsed.port or 443
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((parsed.hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                return {"tls_version": ssock.version() or "unknown"}
    except Exception as e:
        return {"tls_error": str(e)}


def print_user_summary(findings):
    if not findings:
        print("\n[!] No clear vulnerability indicators were found during reconnaissance.")
        return

    print("\n=== VULNERABILITY SUMMARY ===")
    discovered = set()
    for category, items in findings.items():
        if not items:
            continue
        risk = FINDING_CATEGORY_RISK_MAP.get(category)
        if risk:
            discovered.add(risk)
            print(f"- {category}: {risk} ({len(items)} item(s) found)")
        elif category in {"Discovered Internal Links", "Subdomain Candidates"}:
            print(f"- {category}: {len(items)} entries discovered")
        else:
            print(f"- {category}: {len(items)} item(s) found")

    if discovered:
        print("\nPrimary risks identified:")
        for risk in sorted(discovered):
            print(f"  * {risk}")
    print("=== END OF SUMMARY ===\n")


def build_export_payload(base_url, findings, scanner_settings):
    return {
        "target": base_url,
        "scanned_at": datetime.utcnow().isoformat() + "Z",
        "scanner_settings": scanner_settings,
        "findings": findings,
    }


def write_json_output(output_path, payload):
    with open(output_path, 'w', encoding='utf-8') as json_file:
        json.dump(payload, json_file, indent=2)
    print(f"[+] Structured JSON results written to {output_path}")


def write_sarif_output(output_path, payload):
    rules = []
    results = []
    for category, items in payload["findings"].items():
        rule_id = category.replace(' ', '_').upper()
        rule = {
            "id": rule_id,
            "name": category,
            "shortDescription": {"text": category},
            "fullDescription": {"text": payload["scanner_settings"].get("summary", category)},
            "properties": {"category": category}
        }
        rules.append(rule)
        for item in items:
            results.append({
                "ruleId": rule_id,
                "level": "warning",
                "message": {"text": f"{category}: {item}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": payload["target"]}
                    }
                }],
                "properties": {"category": category}
            })

    sarif_document = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ReconScanner",
                    "informationUri": "https://github.com/",
                    "rules": rules,
                }
            },
            "results": results,
            "properties": {
                "scanned_at": payload["scanned_at"],
                "scanner_settings": payload["scanner_settings"],
            }
        }]
    }

    with open(output_path, 'w', encoding='utf-8') as sarif_file:
        json.dump(sarif_document, sarif_file, indent=2)
    print(f"[+] SARIF output written to {output_path}")


def map_target_ecosystem(base_url, max_depth=2, max_pages=200, workers=20, delay=0, proxy=None, state_db=None, resume=False, enable_dom_xss=False):
    """Scrapes the target to collect asset, header, directory, and JS reconnaissance data."""
    print(f"[*] Analyzing target infrastructure: {base_url}")
    session = requests.Session()
    if proxy:
        session.proxies.update(parse_proxy_string(proxy))
        session.trust_env = False

    state_store = ScanStateDB(state_db) if state_db else None
    if state_store and resume:
        state_store.seed_url(base_url, 0)

    try:
        _, pages = crawl_internal_links(
            base_url,
            session,
            max_depth=max_depth,
            max_pages=max_pages,
            workers=workers,
            delay=delay,
            state_store=state_store,
        )
    except Exception as e:
        print(f"[-] Crawling failed: {e}")
        return "", {}

    js_urls = set()
    findings = state_store.load_findings() if state_store else {}
    internal_links = set()

    for page_url, page_text, soup in pages:
        internal_links.add(page_url)
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                js_urls.add(urllib.parse.urljoin(page_url, src))
        page_signals = extract_content_signals(page_text, page_url)
        for cat, items in page_signals.items():
            findings.setdefault(cat, []).extend(items)
            if state_store:
                for item in items:
                    state_store.add_finding(cat, item, page_url)
        param_signals = extract_query_parameter_signals(page_url)
        if param_signals:
            findings.setdefault("Suspicious Query Parameters", []).extend(param_signals)
            if state_store:
                for item in param_signals:
                    state_store.add_finding("Suspicious Query Parameters", item, page_url)

        lib_vulns = detect_library_version_vulnerabilities(page_text)
        for cat, items in lib_vulns.items():
            findings.setdefault(cat, []).extend(items)
            if state_store:
                for item in items:
                    state_store.add_finding(cat, item, page_url)

    for js_url in js_urls:
        js_signals = fetch_and_extract_js_live(js_url, session, delay=delay)
        for cat, items in js_signals.items():
            findings.setdefault(cat, []).extend(items)
            if state_store:
                for item in items:
                    state_store.add_finding(cat, item, js_url)

    if enable_dom_xss:
        for page_url in list(internal_links)[:5]:
            xss_result = verify_dom_xss(page_url)
            if xss_result:
                findings.setdefault("Automated DOM XSS", []).append(xss_result)
                if state_store:
                    state_store.add_finding("Automated DOM XSS", xss_result, page_url)

    deep_dirs = probe_deep_directories(base_url, session, delay=delay)
    subdomains = probe_subdomains(base_url, session, delay=delay)
    header_status = get_security_headers(base_url, session, delay=delay)
    tls_status = get_tls_info(base_url)

    findings["Discovered Internal Links"] = list(internal_links)[:50]
    findings["Deep Directory Probes"] = deep_dirs[:25]
    findings["Subdomain Candidates"] = subdomains[:25]
    findings["Security Headers"] = [f"{k}: {v}" for k, v in header_status.items()]
    findings["TLS Info"] = [f"{k}: {v}" for k, v in tls_status.items()]

    print_user_summary(findings)

    prompt_buffer = "### SECURITY AUDIT DOSSIER\n"
    prompt_buffer += f"Target Domain: {base_url}\n\n"
    for category, elements in findings.items():
        prompt_buffer += f"#### {category}\n"
        for el in elements[:25]:
            prompt_buffer += f"- `{el}`\n"
        prompt_buffer += "\n"

    return prompt_buffer, findings


def query_ai_engine_legacy(recon_data):
    """Pipes data directly into the AI engine and prints a real-time live response stream."""
    gemini_api_key = os.environ.get("GEMINI_API_KEY")
    
    system_instruction = (
        "You are a strict, cynical penetration testing assistant. If the evidence is incomplete, do not infer a vulnerability. "
        "Only flag high-confidence issues. Review the extracted reconnaissance metrics and identify only those vulnerability classes supported by credible evidence. "
        "Flag sensitive data leaks, insecure headers, weak TLS, dangerous client-side sinks, outdated libraries, exposed directories, hidden subdomains, and risky query parameters. "
        "Summarize findings clearly and prioritize the highest-severity issues first. "
        "Provide concise recommendations for immediate remediation or deeper manual testing."
    )

    if gemini_api_key:
        print("\n[*] Initializing cloud AI engine (Gemini API)...")
        try:
            client = genai.Client(api_key=gemini_api_key)
            # Use generate_content_stream to print results live token-by-token
            response_stream = client.models.generate_content_stream(
                model='gemini-2.5-flash',
                contents=recon_data,
                config=types.GenerateContentConfig(
                    system_instruction=system_instruction,
                    temperature=0.2
                )
            )
            print("\n=== LIVE AI VULNERABILITY ANALYSIS ===\n")
            for chunk in response_stream:
                print(chunk.text, end="", flush=True)
            print("\n======================================\n")
        except Exception as e:
            print(f"[-] Cloud API Error: {e}")
    else:
        # Fallback to local offline model if you run Ollama locally on your computer
        print("\n[*] GEMINI_API_KEY environment variable not set.")
        print("[*] Falling back to local offline AI model (Ollama - Llama3)...")
        try:
            local_payload = {
                "model": "llama3",
                "prompt": f"{system_instruction}\n\nData:\n{recon_data}",
                "stream": True
            }
            # Stream response directly from localhost
            res = requests.post("http://localhost:11434/api/generate", json=local_payload, stream=True)
            print("\n=== LIVE LOCAL AI ANALYSIS ===\n")
            for line in res.iter_lines():
                if line:
                    import json
                    json_data = json.loads(line.decode('utf-8'))
                    print(json_data.get("response", ""), end="", flush=True)
            print("\n==============================\n")
        except Exception:
            print("[-] Local AI engine not detected. Please install Ollama or export your GEMINI_API_KEY.")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan a website for reconnaissance signals and generate a vulnerability-oriented AI prompt."
    )
    parser.add_argument("target", help="Target base URL to scan, e.g. https://example.com")
    parser.add_argument("--no-ai", action="store_true", help="Do not invoke the AI engine; only perform reconnaissance and summary output.")
    parser.add_argument("--max-pages", type=int, default=200, help="Maximum number of pages to crawl for large sites.")
    parser.add_argument("--max-depth", type=int, default=2, help="Maximum internal link depth to follow.")
    parser.add_argument("--workers", type=int, default=20, help="Number of concurrent page fetch workers.")
    parser.add_argument("--delay", type=float, default=0.0, help="Base delay in seconds for randomized jitter between requests.")
    parser.add_argument("--proxy", help="Optional upstream proxy URL for Burp Suite, Tor, or other interception.")
    parser.add_argument("--state-db", help="Optional SQLite path for scan state persistence and resume support.")
    parser.add_argument("--resume", action="store_true", help="Resume a previously saved scan state from the SQLite database.")
    parser.add_argument("--dom-xss", action="store_true", help="Enable optional headless DOM XSS verification when Playwright is available.")
    parser.add_argument("--output-json", help="Write structured JSON scan results to this file.")
    parser.add_argument("--output-sarif", help="Write SARIF scan results to this file.")
    args = parser.parse_args()

    prompt_data, findings = map_target_ecosystem(
        args.target,
        max_depth=args.max_depth,
        max_pages=args.max_pages,
        workers=args.workers,
        delay=args.delay,
        proxy=args.proxy,
        state_db=args.state_db,
        resume=args.resume,
        enable_dom_xss=args.dom_xss,
    )

    if args.output_json or args.output_sarif:
        export_payload = build_export_payload(
            args.target,
            findings,
            {
                "max_pages": args.max_pages,
                "max_depth": args.max_depth,
                "workers": args.workers,
                "delay": args.delay,
                "summary": "Reconnaissance scan output for automated ingestion.",
            }
        )
        if args.output_json:
            write_json_output(args.output_json, export_payload)
        if args.output_sarif:
            write_sarif_output(args.output_sarif, export_payload)

    if prompt_data and not args.no_ai:
        query_ai_engine(prompt_data, findings)


if __name__ == "__main__":
    main()

