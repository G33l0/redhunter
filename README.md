# RedHunter v1.3
### Web Vulnerability & Recon Framework

```
██████╗ ███████╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔════╝██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝█████╗  ██║  ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██╗██╔══╝  ██║  ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║  ██║███████╗██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

> **Authorized Use Only** | Author: `g33l0` | Telegram: `@x0x0h33l0`

---

## What Is RedHunter?

RedHunter is a professional Python security recon tool that scans web targets for:

- **Exposed `.env` files** containing real credentials — database passwords, API keys, cloud tokens
- **Sensitive files** accidentally left public — git repos, SSH keys, backup SQL dumps, config files
- **Dangerous admin surfaces** — phpMyAdmin, cPanel, WHM, Plesk login panels
- **WordPress vulnerabilities** — plugin CVE fingerprinting, XML-RPC, user enumeration
- **Cloud misconfigurations** — AWS/GCP/Azure metadata endpoints, exposed credentials
- **CI/CD and container leaks** — Kubernetes configs, Docker secrets, pipeline YAML files

Built for security monitoring services and authorized penetration testing engagements.

---

## Installation

**Requires:** Python 3.8+

```bash
git clone https://github.com/YOUR_USERNAME/redhunter.git
cd redhunter
pip install -r requirements.txt
```

---

## Quick Start

### Interactive wizard (recommended)
```bash
python redhunter.py
```
No flags needed. The wizard walks you through every option step by step.

### Single target — exposure scan
```bash
python redhunter.py -u https://example.com
```

### Single target — full scan with CVE checks
```bash
python redhunter.py -u https://example.com --vuln-scan
```

### Bulk targets from file
```bash
python redhunter.py -f targets.txt --vuln-scan --json --html
```

### Vulnerability check only (fastest — skips 300+ path probes)
```bash
python redhunter.py -u https://example.com --vuln-only
```

### With Telegram alerts
```bash
python redhunter.py -f targets.txt --tg-token YOUR_TOKEN --tg-chat YOUR_CHAT_ID
```

### Scheduled daily scan
```bash
python redhunter.py -f targets.txt --schedule 24 --tg-token TOKEN --tg-chat ID --all-reports
```

## Scan Modules (20 total)

| Module | Risk | What It Detects |
|--------|------|----------------|
| `env_files` | CRITICAL | `.env`, `.env.local`, `.env.production`, Node.js/Laravel/Docker variants (40+ paths) |
| `config_files` | CRITICAL | `wp-config.php`, `database.yml`, `settings.py`, `appsettings.json` with real credentials |
| `backup_files` | CRITICAL | SQL database dumps, `.zip`/`.tar.gz` site backups, `mysqldump` exports |
| `ssh_keys` | CRITICAL | `id_rsa`, `id_ed25519`, `server.key`, PEM private keys exposed in web root |
| `cloud_metadata` | CRITICAL | AWS IMDSv1, GCP metadata, Azure IMDS, `.aws/credentials`, service account JSON |
| `exposed_secrets` | CRITICAL | `.netrc`, `credentials.json`, `sftp-config.json`, GCP service accounts, OAuth secrets |
| `database_exposure` | CRITICAL | `mysql.conf`, `redis.conf`, `pg_hba.conf`, exposed CSV/JSON with user data |
| `git_exposure` | HIGH | `.git/config`, `.git/HEAD`, packed-refs — full source code recovery possible |
| `devops_files` | HIGH | `docker-compose.yml`, `Dockerfile` — often contains registry credentials and secrets |
| `cicd_exposure` | HIGH | `.gitlab-ci.yml`, `.travis.yml`, `Jenkinsfile`, deploy scripts with embedded secrets |
| `kubernetes` | HIGH | `k8s.yaml`, `secrets.yaml`, `helm-values.yml`, kubeconfig files |
| `phpmyadmin` | MEDIUM | phpMyAdmin, Adminer database admin panels (login required, but exposes attack surface) |
| `admin_panels` | MEDIUM | cPanel, WHM, Plesk, DirectAdmin, Django/Joomla admin login pages |
| `php_info` | MEDIUM | `phpinfo()` pages revealing server internals, PHP version, config paths |
| `log_files` | MEDIUM | Laravel, application, and error logs — often contain stack traces with DB errors |
| `wordpress` | MEDIUM | REST API user enumeration, `debug.log`, XML-RPC surface, `wp-admin/install.php` |
| `server_status` | LOW | Apache/Nginx server-status, Spring Actuator health/env/mappings endpoints |
| `api_exposure` | LOW | Swagger UI, OpenAPI/GraphQL schema documents |
| `package_files` | LOW | `composer.json`, `package.json`, `requirements.txt` — dependency disclosure |
| `phpmyadmin` | LOW | `phpMyAdmin` DB admin |

---

## CVE Database (v1.1)

| CVE | Plugin | CVSS | Type |
|-----|--------|------|------|
| CVE-2026-2446 | powerpack-for-learndash | 9.8 | Unauthenticated Option Update |
| CVE-2026-3459 | drag-and-drop-file-upload-cf7 | 9.8 | Unauthenticated File Upload → RCE |
| Zero-day | reflex-gallery | 9.8 | Legacy PHP FileUploader → RCE |
| CVE-2020-25213 | wp-file-manager | 9.8 | elFinder RCE |
| CVE-2023-32243 | essential-addons-for-elementor | 9.8 | Privilege Escalation |
| CVE-2024-27956 | wp-automatic | 9.9 | SQL Injection / RCE |
| CVE-2023-6553 | backup-migration | 9.8 | PHP Code Injection → RCE |

---

## Speed Tuning

| Scenario | Recommended Settings |
|----------|---------------------|
| Single target, maximum speed | `--threads 1 --path-workers 60` |
| 10-50 targets, balanced | `--threads 25 --path-workers 30` |
| 100+ targets, large list | `--threads 50 --path-workers 20` |
| Stealth / polite scan | `--threads 10 --delay 1` |
| CVE check only, large list | `--vuln-only --threads 50` |

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `-u, --url` | Single target URL |
| `-f, --file` | File with target URLs (one per line) |
| `-t, --threads` | Outer target threads (default: 25) |
| `--path-workers` | Path workers per target (default: 20) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `--delay` | Delay between targets in seconds |
| `--vuln-scan` | Combined: exposure + CVE fingerprinting |
| `--vuln-only` | CVE fingerprinting only, skip exposure |
| `--proxy` | HTTP/SOCKS5 proxy URL |
| `--aggressive` | Check all content types |
| `-H, --headers` | Custom request headers |
| `--tg-token` | Telegram bot token |
| `--tg-chat` | Telegram chat or group ID |
| `--tg-test` | Send test message and exit |
| `--schedule` | Repeat every N hours |
| `--discover` | Seed domains for asset discovery |
| `--shodan-key` | Shodan API key |
| `--censys-id / --censys-secret` | Censys API credentials |
| `-o, --output` | Output directory (default: `./reports`) |
| `--json` | Save JSON report |
| `--txt` | Save TXT report |
| `--html` | Save HTML report |
| `--all-reports` | Save JSON + TXT + HTML |
| `--redact` | Redact secret values in all output |
| `--show-content` | Print raw `.env` content to terminal |
| `--history` | View previously stored findings |
| `-v, --verbose` | Print every URL probed |
| `-q, --quiet` | Suppress banner and progress |

---

## Telegram Alerts

1. Create a bot at [@BotFather](https://t.me/BotFather) — save the token
2. Add the bot to your team's private channel or group
3. Get your chat ID: `https://api.telegram.org/bot<TOKEN>/getUpdates`
4. Test connection: `python redhunter.py --tg-token TOKEN --tg-chat ID --tg-test`

RedHunter sends separate alerts for:
- `.env` file exposures (with risk level and matched secret categories)
- Web exposure findings (phpMyAdmin, Git, backups, etc.)
- Plugin CVE findings (with CVSS score, description, recommended action)
- Scan summary at completion

---

## Output Files

Reports save to `./reports/` by default:
```
reports/
├── redhunter_20260307_143022.json   ← machine-readable, includes all findings + vulns
├── redhunter_20260307_143022.txt    ← human-readable text summary
└── redhunter_20260307_143022.html   ← styled HTML report, shareable with clients
```

The `reports/` directory is in `.gitignore` and will never be committed to GitHub.

---

## Asset Discovery

RedHunter can auto-discover subdomains before scanning:
```bash
python redhunter.py --discover example.com --vuln-scan --all-reports
```

Sources (no API key required):
- **crt.sh** — SSL certificate transparency logs
- **HackerTarget** — passive subdomain enumeration
- **AlienVault OTX** — passive DNS records

API-based sources (key required):
- **Shodan** — `--shodan-key YOUR_KEY --shodan-query "hostname:example.com"`
- **Censys** — `--censys-id ID --censys-secret SECRET`

---

## Legal

This tool is for **authorized security assessments only.**

You must have written permission to scan any target. Unauthorized scanning violates computer crime laws in most jurisdictions.

See `LICENSE` for full terms.

---

## Team Notes

- Run only against targets listed in your signed client monitoring agreements
- Reports auto-saved to `reports/` — back these up externally
- State database (`redhunter_state.db`) tracks findings between runs — delete it to reset
- Add bot to a **private** Telegram channel only — scan results contain sensitive data
- Use `--redact` flag when generating reports that will be shared externally
