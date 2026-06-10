# Website Reconnaissance and Vulnerability Scanner

[![CI](https://github.com/<your-org>/<your-repo>/actions/workflows/main.yml/badge.svg)](https://github.com/<your-org>/<your-repo>/actions/workflows/main.yml)
[![Docker Image](https://img.shields.io/badge/docker-ready-blue.svg)](https://hub.docker.com/)

This repository contains a production-ready reconnaissance scanner designed for security teams, bug bounty hunters, and CI/CD automation.
The script combines stealthy crawling, rotating browser fingerprints, structured output, optional AI analysis, and resume-capable scan state persistence.

## Architecture Overview

```text
Target URL --> Crawling Engine --> Stealth request layer (User-Agent + jitter + proxy)
                   |                          |
                   |                          --> Optional Burp/Tor proxy
                   |                          --> SQLite resume state
                   v
            Content extraction
                   |
                   +--> JS/source-map scanning
                   +--> dependency version detection + OSV lookup
                   +--> security header and TLS checks
                   +--> optional headless DOM XSS verification
                   v
           Findings output + AI validation
                   |
                   +--> JSON or SARIF export
                   +--> two-tier AI verifier (Finder + Critic)
```

## Requirements

- Python 3.10+
- `requests`
- `beautifulsoup4`
- `google-genai`
- `playwright` (optional for DOM XSS verification)
- `black`, `flake8`, `bandit` (for CI)

Install all supported dependencies:

```powershell
python -m pip install -r requirements.txt
```

## Usage

Run a standard scan:

```powershell
python main.py https://example.com
```

Run a stealthier scan using randomized delays and a proxy:

```powershell
python main.py https://example.com --delay 1.5 --proxy http://127.0.0.1:8080 --workers 10
```

Resume an interrupted scan with SQLite state persistence:

```powershell
python main.py https://example.com --state-db scan_state.sqlite --resume --output-json findings.json
```

Export structured results for automation:

```powershell
python main.py https://example.com --output-json findings.json --output-sarif findings.sarif
```

Optional DOM XSS verification (requires Playwright):

```powershell
python main.py https://example.com --dom-xss
```

## CLI Options

- `--no-ai` : skip AI analysis and only perform reconnaissance
- `--max-pages N` : maximum number of pages to crawl
- `--max-depth N` : maximum internal link depth to follow
- `--workers N` : number of concurrent fetch workers
- `--delay N` : base per-request delay; randomized jitter is applied
- `--proxy URL` : upstream proxy for Burp Suite, Tor, or interception
- `--state-db PATH` : SQLite file for scan persistence and resume support
- `--resume` : continue scanning from the existing SQLite state file
- `--dom-xss` : enable optional headless DOM XSS verification
- `--output-json FILE` : save structured JSON output
- `--output-sarif FILE` : save SARIF-compliant output

## Example Output

```text
=== VULNERABILITY SUMMARY ===
- Potential Credentials: Secret or credential exposure (3 item(s) found)
- Dependency Vulnerabilities: Outdated third-party package with CVE references (1 item(s) found)
- Security Headers: Missing HTTP security headers (5 item(s) found)
Primary risks identified:
  * Secret or credential exposure
  * Outdated or vulnerable third-party dependencies
=== END OF SUMMARY ===
```

## Docker

Build and run the scanner with Docker:

```powershell
docker build -t ai-web-scanner .
docker run --rm ai-web-scanner --delay 1.2 --output-json findings.json https://example.com
```

## CI/CD

This repository includes a GitHub Actions workflow that runs formatting, linting, bandit security checks, and syntax validation on every push and pull request.
