#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                    ║
║  ██████╗ ███████╗██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗   ║
║  ██╔══██╗██╔════╝██╔══██╗    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗  ║
║  ██████╔╝█████╗  ██║  ██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝  ║
║  ██╔══██╗██╔══╝  ██║  ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗  ║
║  ██║  ██║███████╗██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║  ║
║  ╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝  ║
║                                                                                    ║
║                REDHUNTER — Web Vulnerability & Recon Framework                     ║
║                     Author : g33l0  |  Telegram : @x0x0h33l0                       ║
╚════════════════════════════════════════════════════════════════════════════════════╝

  AUTHORIZED USE ONLY — For use on systems you own or have explicit
  written authorization to test. Unauthorized use is illegal.
  RedHunter is a detection & fingerprinting framework for red teams.
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import os
import sys
import re
import json
import time
import random
import hashlib
import sqlite3
import argparse
import threading
import queue
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Optional, List

# ── signal: SIGINT is the only cross-platform-safe signal ────────────────────
import signal
import html
import importlib

# ── third-party: caught with helpful messages if missing ─────────────────────
def _require(pkg, install_name=None):
    try:
        return importlib.import_module(pkg)
    except ImportError:
        name = install_name or pkg
        # On Windows, 'python' and 'python3' can point to different installs.
        # Show both pip and pip3 commands so the user uses the right one.
        win_note = (
            "\n  Windows tip: run the pip that matches the python you used to\n"
            "  launch this script. If 'python redhunter.py' use 'pip install'.\n"
            "  If 'python3 redhunter.py' use 'pip3 install'.\n"
            "  Or use: python -m pip install " + name
        ) if os.name == "nt" else ""
        print(f"\n[ERROR] Missing package '{name}'. Install it with:\n"
              f"        pip install {name}\n"
              f"  or install all requirements:\n"
              f"        pip install -r requirements.txt"
              + win_note + "\n")
        sys.exit(1)

requests  = _require("requests")
colorama  = _require("colorama")
rich_mod  = _require("rich")
schedule  = _require("schedule")

import urllib3
from colorama import init
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Prompt, Confirm
from rich import box

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)
console = Console()

# ─── META ─────────────────────────────────────────────────────────────────────
VERSION   = "1.2"
AUTHOR    = "g33l0"
TG_HANDLE = "@x0x0h33l0"
DB_PATH   = "redhunter_state.db"

BANNER = f"""[bold red]
╔════════════════════════════════════════════════════════════════════════════════════════╗
║                                                                                        ║
║     ██████╗ ███████╗██████╗     ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗    ║
║     ██╔══██╗██╔════╝██╔══██╗    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗   ║
║     ██████╔╝█████╗  ██║  ██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝   ║
║     ██╔══██╗██╔══╝  ██║  ██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗   ║
║     ██║  ██║███████╗██████╔╝    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║   ║
║     ╚═╝  ╚═╝╚══════╝╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝   ║
║                                                                                        ║
║             [bold white]  ░▒▓ REDHUNTER — Web Vulnerability & Recon Framework  v{VERSION} ▓▒░  [/bold white][bold red]          ║
║            [bold yellow]  Author : {AUTHOR}[/bold yellow][bold red]  |  [bold green]Telegram : {TG_HANDLE}[/bold green][bold red]  |  [dim red]Authorized Use Only[/dim red][bold red]          ║
╚════════════════════════════════════════════════════════════════════════════════════════╝[/bold red]"""

# ─── SCAN MODULES ─────────────────────────────────────────────────────────────
# Each module is a named group of paths. The engine checks ALL enabled modules.
# Add new modules here without touching the scan engine.

SCAN_MODULES: dict = {

    # ── Already existed in v3.x ──────────────────────────────────────────────
    "env_files": {
        "enabled": True,
        "label":   ".env Files",
        "paths": [
            "/.env", "/.env.local", "/.env.dev", "/.env.development",
            "/.env.prod", "/.env.production", "/.env.staging", "/.env.backup",
            "/.env.bak", "/.env.old", "/.env.example", "/.env.sample",
            "/.env.test", "/.env.php", "/.env.save", "/.env.copy",
            "/.env.dist", "/.env.secret",
            "/api/.env", "/backend/.env", "/app/.env", "/config/.env",
            "/src/.env", "/public/.env", "/web/.env", "/www/.env",
            "/laravel/.env", "/wp-content/.env", "/application/.env",
            "/server/.env", "/deploy/.env", "/docker/.env",
            "/storage/.env", "/core/.env", "/portal/.env",
        
                "/.env.local.php",
                "/.env.production.local",
                "/.env.development.local",
                "/site/.env",
                "/.env_1",
                "/env",
                "/env.txt",
                "/.env.orig",
                "/.env~",
                "/._env",],
    },

    # ── NEW: phpMyAdmin & DB Admin Tools ─────────────────────────────────────
    "phpmyadmin": {
        "enabled": True,
        "label":   "phpMyAdmin / DB Admin",
        "paths": [
            "/phpmyadmin/", "/phpmyadmin/index.php",
            "/phpMyAdmin/", "/phpMyAdmin/index.php",
            "/pma/", "/pma/index.php",
            "/admin/phpmyadmin/", "/db/", "/dbadmin/",
            "/mysql/", "/mysqladmin/", "/phpmyadmin2/",
            "/phpmyadmin3/", "/phpmyadmin4/",
            "/myadmin/", "/sqlmanager/", "/mysqlmanager/",
            "/php-myadmin/", "/phpmy-admin/",
            "/adminer.php", "/adminer/",
            "/adminer-4.php", "/adminer-4.7.9.php",
        ],
    },

    # ── NEW: Admin Panels ─────────────────────────────────────────────────────
    "admin_panels": {
        "enabled": True,
        "label":   "Admin Panels",
        "paths": [
            "/admin/", "/admin/login", "/admin/login.php", "/admin/index.php",
            "/administrator/", "/administrator/index.php",
            "/adminpanel/", "/admin-panel/", "/wp-admin/",
            "/user/login", "/auth/login",
            "/backend/", "/backend/login", "/control/",
            "/controlpanel/", "/cp/", "/cpanel/",
            "/manage/", "/management/", "/manager/",
            "/moderator/", "/superadmin/", "/siteadmin/",
            "/webadmin/", "/adminarea/", "/bb-admin/",
            "/adminLogin/", "/admin_area/", "/panel-administracion/",
            "/instadmin/", "/memberadmin/", "/administratorlogin/",
        
                "/admin/config",
                "/manager/html",
                "/sql/",],
    },

    # ── NEW: PHP Info & Debug Pages ───────────────────────────────────────────
    "php_info": {
        "enabled": True,
        "label":   "PHP Info / Debug",
        "paths": [
            "/phpinfo.php", "/info.php", "/php_info.php", "/phpinfo/",
            "/test.php", "/info/", "/?phpinfo=1",
            "/debug/", "/debug/default/view", "/debug/vars",
            "/_profiler/", "/_profiler/phpinfo",
            "/telescope", "/telescope/requests",
            "/horizon", "/clockwork/app", "/__clockwork/",
            "/debugbar/",
        ],
    },

    # ── NEW: Server Status & Version Disclosure ───────────────────────────────
    "server_status": {
        "enabled": True,
        "label":   "Server Status / Info",
        "paths": [
            "/server-status", "/server-info",
            "/nginx_status", "/status",
            "/actuator", "/actuator/health",
            "/actuator/env", "/actuator/info",
            "/actuator/mappings", "/actuator/beans",
            "/actuator/logfile", "/actuator/httptrace",
            "/metrics", "/health", "/healthz",
            "/ready", "/readyz", "/live", "/livez",
            "/_cat/indices", "/_cat/nodes",
            "/_cluster/health",
            "/solr/", "/solr/admin/",
            "/jmx", "/jolokia/",
        ],
    },

    # ── NEW: Exposed Config Files ─────────────────────────────────────────────
    "config_files": {
        "enabled": True,
        "label":   "Config Files",
        "paths": [
            "/config.php", "/config/config.php", "/configuration.php",
            "/config/database.php", "/config/app.php",
            "/wp-config.php", "/wp-config.php.bak",
            "/config.inc.php", "/settings.php", "/settings.inc.php",
            "/database.php", "/db.php", "/db_config.php",
            "/conf/config.php", "/includes/config.php",
            "/application/config/database.php",
            "/app/config/database.php",
            "/sites/default/settings.php",
            "/config/settings.inc.php",
            "/config.xml", "/config.json",
            "/config.yml", "/config.yaml", "/.config",
            "/config/config.yml", "/config/config.yaml",
            "/app/config/parameters.yml",
            "/app/config/parameters.yaml",
        
                "/includes/database.php",
                "/conf/config.ini",
                "/config/settings.php",
                "/settings.py",
                "/local_settings.py",
                "/appsettings.json",
                "/Web.config",
                "/web.config",
                "/.npmrc",
                "/.pypirc",
                "/Gemfile",
                "/.htpasswd",],
    },

    # ── NEW: Backup & Database Dumps ─────────────────────────────────────────
    "backup_files": {
        "enabled": True,
        "label":   "Backup / Dump Files",
        "paths": [
            "/backup.sql", "/backup.sql.gz", "/dump.sql",
            "/database.sql", "/db.sql", "/db_backup.sql",
            "/backup/", "/backups/", "/backup.zip",
            "/backup.tar.gz", "/backup.tar",
            "/site.tar.gz", "/website.zip", "/www.zip",
            "/public_html.zip", "/html.zip",
            "/db_dump.sql", "/mysqldump.sql",
            "/latest.sql", "/prod.sql", "/production.sql",
        
                "/dump.sql.gz",
                "/database.sql.gz",
                "/files.tar.gz",
                "/htdocs.tar.gz",
                "/public_html.tar.gz",],
    },

    # ── NEW: Git / VCS Exposure ───────────────────────────────────────────────
    "git_exposure": {
        "enabled": True,
        "label":   "Git / VCS Exposure",
        "paths": [
            "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
            "/.git/index", "/.git/packed-refs",
            "/.gitignore", "/.gitmodules", "/.gitattributes",
            "/.svn/entries", "/.svn/wc.db",
            "/.hg/hgrc", "/.bzr/README",
            "/CVS/Root", "/CVS/Entries",
        
                "/.git/FETCH_HEAD",
                "/.git/refs/heads/master",
                "/.git/refs/heads/main",
                "/.git/logs/HEAD",
                "/.git/info/refs",],
    },

    # ── NEW: Log Files ────────────────────────────────────────────────────────
    "log_files": {
        "enabled": True,
        "label":   "Log Files",
        "paths": [
            "/logs/", "/log/", "/error.log", "/error_log",
            "/access.log", "/access_log",
            "/app/storage/logs/laravel.log",
            "/storage/logs/laravel.log",
            "/storage/logs/",
            "/logs/error.log", "/logs/app.log",
            "/logs/debug.log", "/site/logs/",
            "/.npm-debug.log", "/npm-debug.log",
            "/yarn-error.log", "/debug.log",
        ],
    },

    # ── NEW: SSH Keys & Certificates ─────────────────────────────────────────
    "ssh_keys": {
        "enabled": True,
        "label":   "SSH Keys / Certs",
        "paths": [
            "/.ssh/id_rsa", "/.ssh/id_dsa", "/.ssh/id_ecdsa",
            "/.ssh/id_ed25519", "/.ssh/authorized_keys",
            "/.ssh/known_hosts", "/.ssh/config",
            "/id_rsa", "/id_rsa.pub",
            "/server.key", "/private.key",
            "/ssl.key", "/ssl.crt", "/server.crt",
        
                "/id_dsa",
                "/id_ecdsa",
                "/id_ed25519",
                "/server.pem",
                "/privatekey.pem",],
    },

    # ── NEW: Composer / Package Manifests ────────────────────────────────────
    "package_files": {
        "enabled": True,
        "label":   "Package / Dependency Files",
        "paths": [
            "/composer.json", "/composer.lock",
            "/package.json", "/package-lock.json",
            "/yarn.lock", "/Gemfile", "/Gemfile.lock",
            "/requirements.txt", "/Pipfile", "/Pipfile.lock",
            "/go.mod", "/go.sum",
        ],
    },

    # ── NEW: Docker / DevOps / CI ─────────────────────────────────────────────
    "devops_files": {
        "enabled": True,
        "label":   "Docker / DevOps / CI",
        "paths": [
            "/docker-compose.yml", "/docker-compose.yaml",
            "/docker-compose.override.yml",
            "/docker-compose.prod.yml",
            "/Dockerfile", "/.dockerignore",
            "/kubernetes.yml", "/k8s.yml",
            "/.travis.yml", "/.circleci/config.yml",
            "/Jenkinsfile",
            "/ansible.cfg", "/playbook.yml",
            "/terraform.tfvars", "/Vagrantfile",
        ],
    },

    # ── NEW: API Docs & GraphQL ───────────────────────────────────────────────
    "api_exposure": {
        "enabled": True,
        "label":   "API Docs / GraphQL",
        "paths": [
            "/swagger.json", "/swagger.yaml",
            "/swagger-ui/", "/swagger-ui.html",
            "/api-docs/", "/api-docs.json",
            "/openapi.json", "/openapi.yaml",
            "/v1/api-docs", "/v2/api-docs",
            "/graphql", "/graphiql", "/playground",
            "/api/swagger", "/docs/api",
        ],
    },

    # ── NEW: WordPress Specific ───────────────────────────────────────────────
    # Note: wp-login.php removed — it is a normal page, not an exposure.
    # We target paths that genuinely leak data when publicly accessible.
    "wordpress": {
        "enabled": True,
        "label":   "WordPress",
        "paths": [
            "/wp-json/wp/v2/users",     # user enumeration via REST API
            "/wp-content/debug.log",    # debug log — may contain DB errors, passwords
            "/wp-content/uploads/.htaccess",  # htaccess may be missing, exposing uploads
            "/xmlrpc.php",              # XML-RPC — brute force / info disclosure
            "/?author=1",               # legacy author enumeration
            "/wp-config-sample.php",    # config sample — may contain real credentials
            "/wp-admin/install.php",    # re-installation page — should be inaccessible post-install
        ],
    },

    # ── NEW: Cloud Metadata & IMDSv1 ─────────────────────────────────────────
    # AWS, GCP, Azure, DigitalOcean IMDSv1 endpoints accessible from mis-routed
    # apps or SSRF chains. Should NEVER be reachable from the public internet.
    "cloud_metadata": {
        "enabled": True,
        "label":   "Cloud Metadata / IMDS",
        "paths": [
            "/latest/meta-data/",                          # AWS IMDSv1
            "/latest/meta-data/iam/security-credentials/",# AWS creds via IMDS
            "/latest/user-data",                           # AWS user-data (often has secrets)
            "/metadata/v1/",                               # DigitalOcean
            "/metadata/instance?api-version=2021-02-01",   # Azure IMDS
            "/computeMetadata/v1/",                        # GCP
            "/computeMetadata/v1/project/project-id",      # GCP project ID
            "/computeMetadata/v1/instance/service-accounts/default/token",  # GCP token
            "/opc/v1/instance/",                           # Oracle Cloud
            "/.aws/credentials",                           # Leaked AWS creds file
            "/.aws/config",                                # AWS config
            "/aws.json", "/aws_credentials.json",
        ],
    },

    # ── NEW: Exposed Secrets & Credential Files ───────────────────────────────
    "exposed_secrets": {
        "enabled": True,
        "label":   "Exposed Credential Files",
        "paths": [
            "/.netrc",                  # FTP/SSH credentials
            "/.pgpass",                 # PostgreSQL password file
            "/credentials.json",        # GCP service account key
            "/service-account.json",    # GCP service account
            "/serviceaccount.json",
            "/google-credentials.json",
            "/client_secret.json",      # OAuth client secret
            "/secrets.json",
            "/secrets.yml", "/secrets.yaml",
            "/secret.json",
            "/api_keys.json",
            "/apikeys.json",
            "/tokens.json",
            "/auth.json",
            "/.boto",                   # Python boto / AWS S3 credentials
            "/sftp-config.json",        # Sublime SFTP plugin — common dev mistake
            "/FTP.json",
            "/wp-config.bak", "/wp-config.php~",
            "/configuration.bak",
            "/settings.bak",
        ],
    },

    # ── NEW: CI/CD Pipeline & Build Files ────────────────────────────────────
    "cicd_exposure": {
        "enabled": True,
        "label":   "CI/CD / Build Exposure",
        "paths": [
            "/.github/workflows/",
            "/.gitlab-ci.yml",
            "/.travis.yml",
            "/.circleci/config.yml",
            "/Jenkinsfile",
            "/bitbucket-pipelines.yml",
            "/.drone.yml",
            "/azure-pipelines.yml",
            "/build.gradle",
            "/pom.xml",
            "/.env.ci",
            "/.env.build",
            "/deploy.sh",
            "/deploy.rb",
            "/Makefile",
            "/makefile",
            "/MAKEFILE",
            "/build.sh",
            "/release.sh",
            "/ci.sh",
        ],
    },

    # ── NEW: Kubernetes & Container Orchestration ─────────────────────────────
    "kubernetes": {
        "enabled": True,
        "label":   "Kubernetes / Container Config",
        "paths": [
            "/kubernetes.yml",
            "/kubernetes.yaml",
            "/k8s.yml", "/k8s.yaml",
            "/kube-config",
            "/.kube/config",
            "/helm-values.yml",
            "/values.yml", "/values.yaml",
            "/secrets.yaml",
            "/deployment.yaml", "/deployment.yml",
            "/configmap.yaml", "/configmap.yml",
            "/service.yaml",
            "/ingress.yaml",
        ],
    },

    # ── NEW: Database & Storage Exposure ──────────────────────────────────────
    "database_exposure": {
        "enabled": True,
        "label":   "Database / Storage Exposure",
        "paths": [
            "/data.json",
            "/database.json",
            "/users.json",
            "/users.csv",
            "/emails.csv",
            "/export.csv",
            "/export.sql",
            "/data.csv",
            "/dump.json",
            "/db.json",
            "/mongodb.conf",
            "/redis.conf",
            "/elasticsearch.yml",
            "/cassandra.yaml",
            "/mysql.conf",
            "/pg_hba.conf",
            "/.pgpass",
        ],
    },

}  # end SCAN_MODULES

# Convenience flat list for backwards-compat (extra_paths etc.)
ENV_PATHS: List[str] = []
for _mod in SCAN_MODULES.values():
    if _mod["enabled"]:
        ENV_PATHS.extend(_mod["paths"])
ENV_PATHS = list(dict.fromkeys(ENV_PATHS))  # deduplicate preserving order

# ─── DETECTION PATTERNS ───────────────────────────────────────────────────────
# Applied to file CONTENT for .env / config / log files.
# Applied to RESPONSE METADATA (headers, URL, body keywords) for page-type checks.

SENSITIVE_PATTERNS = {
    # ── Existing patterns (v3.x) ─────────────────────────────────────────────
    "SMTP / Mail":          r'(?i)(smtp|mail_host|mail_port|mail_user|mail_pass|mailer|sendgrid|mailgun|ses_key)',
    "Database Credentials": r'(?i)(db_pass|db_user|database_url|mysql_pw|postgres_pass|mongo_uri|db_host|db_name|dbPassword|dbUser|databaseUrl|mongoUri)',
    "API Keys":             r'(?i)(api_key|api_secret|api_token|access_key|secret_key|client_secret|consumer_key|apiKey|apiSecret|accessToken|secretKey)',
    "Cloud Credentials":    r'(?i)(aws_access|aws_secret|gcp_key|azure_client|digitalocean_token|cloudflare_api)',
    "Auth / JWT Secrets":   r'(?i)(jwt_secret|app_secret|auth_secret|secret_key|encryption_key|token_secret)',
    "OAuth / SSO":          r'(?i)(oauth_|client_id|client_secret|github_token|google_client|facebook_app)',
    "Passwords":            r'(?i)(password|passwd|pass=|pwd=|passphrase|dbPassword|userPassword|adminPassword|appPassword)',
    "Usernames":            r'(?i)(username|user_name|login_user|admin_user)',
    "Stripe / Payment":     r'(?i)(stripe_key|stripe_secret|paypal_secret|braintree|square_token)',
    "Twilio / SMS":         r'(?i)(twilio_sid|twilio_token|twilio_auth|vonage_api|nexmo_key)',
    "Private Keys/Certs":   r'(?i)(private_key|ssl_key|rsa_key|certificate|pem_file)',
    "Redis / Cache":        r'(?i)(redis_url|redis_pass|redis_host|memcached_pass)',
    "Webhook Secrets":      r'(?i)(webhook_secret|slack_token|discord_token|telegram_bot)',
    "General Secrets":      r'(?im)^[A-Z_]*(SECRET|TOKEN|KEY|CREDENTIAL|PASSWD)[A-Z0-9_]*\s*=\s*\S{8,}',
    # ── Extended patterns (v4.x) ─────────────────────────────────────────────
    "Docker / DevOps":      r'(?i)(docker_pass|registry_pass|ci_token|deploy_key|ansible_pass|vault_token|terraform)',
    "SSH / Private Keys":   r'(?i)(-----BEGIN|RSA PRIVATE|OPENSSH PRIVATE|DSA PRIVATE|EC PRIVATE|ssh-rsa|ssh-ed25519)',
    "Spring Boot Actuator": r'(?i)(spring\.datasource|spring\.security|management\.endpoints)',
    "WordPress Secrets":    r'(?i)(DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|table_prefix)',
    "Laravel App Config":   r'(?i)(APP_KEY=base64|APP_DEBUG=true|APP_ENV=local|cipher=AES)',
    "Database DSN":         r'(?i)(mysql://|postgres://|postgresql://|mongodb://|redis://|sqlite://)',
    "Internal IPs":         r'(?i)(db_host|redis_host|memcached_host|mq_host)[\s]*[=:][\s]*(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)',
}

# ── Per-module content signatures ─────────────────────────────────────────────
# Used by the exposure scanner to validate that a page response is genuinely
# the resource we expect (not a 200 OK catch-all / soft 404).

MODULE_SIGNATURES: dict = {
    # ═══ SIGNATURE DESIGN RULES ═══════════════════════════════════════════════
    # 1. OR logic: ANY single matching signature = confirmed exposure
    # 2. Each signature must be SPECIFIC to the genuine resource
    #    — it must NOT match normal web pages, login forms, or error pages
    # 3. Evidence extracted = the matched line from response (full context)
    # 4. When in doubt, be MORE strict: false negatives are better than
    #    false positives (we alert on what is real, not what might be real)
    # ══════════════════════════════════════════════════════════════════════════

    # ── phpMyAdmin: only fire on pages that ARE phpMyAdmin ───────────────────
    # Generic MySQL login pages (Adminer, custom DB tools) need their own paths
    "phpmyadmin": [
        r'(?i)(id="pma_|class="pma|pmahomme|PMA_VERSION|pma_navigation)',
        r'(?i)<title>\s*phpMyAdmin\s*</title>',
        r'(?i)(pma_token|pma_lang|pma_charset|pmaAbsoluteUri)',
    ],

    # ── Admin panels: specific hosting/framework control panels ONLY ─────────
    # Login forms are NOT an exposure — every site has a login page.
    # We only flag UNPROTECTED admin interfaces that expose data directly.
    # flask-admin/django-admin on a login page is NOT a finding — we need
    # the actual admin content (list views, model data) to be exposed.
    "admin_panels": [
        # ── cPanel / WHM: require elements UNIQUE to the real login interface.
        # "cPanel Redirect" page also contains the word "cpanel" — do NOT match
        # on the bare word. Require the actual login form input names or the
        # cPanel logo/header that only appear on the real panel, not the redirect.
        r'(?i)(id="login_form"[^>]*action="[^"]*cpanel|name="user"[^>]*cpanel)',
        r'(?i)(cpsess|cpanel_jsonapi|WHM\s+\d+|whostmgr\.cgi)',
        r'(?i)<title>[^<]*(WHM|WebHost\s+Manager)[^<]*</title>',
        r'(?i)(id="whmlogin"|class="whm-|whm_username)',
        # ── Plesk / DirectAdmin: specific login form identifiers
        r'(?i)(name="send"[^>]*value="Log In"[^>]*id="plesk|plesk\.com/modules)',
        r'(?i)(directadmin\.com|action="/CMD_LOGIN")',
        r'(?i)(webmin\.cgi|webmin/index\.cgi)',
        # ── CMS admin panels
        r'(?i)(Joomla\s+Administration\s+Login)',
        r'(?i)<title>[^<]*\|\s*Django\s+site\s+admin[^<]*</title>',
        r'(?i)class="flask-admin\b',
    ],

    # ── PHP info: phpinfo() table structure — unique, cannot appear in HTML ──
    # Must match the specific two-column info table phpinfo() generates.
    # class="e" alone is far too broad (any HTML table can have class="e").
    "php_info": [
        r'(?i)PHP\s+Version\s*</td>',
        r'(?i)(Configure\s+Command\s*</td>|Build\s+Date\s*</td>)',
        r'(?i)Loaded\s+Configuration\s+File\s*</td>',
        r'(?i)<title>\s*phpinfo\s*\(\s*\)',
    ],

    # ── Server status: Apache/Nginx/Spring specific output format ────────────
    "server_status": [
        r'(?i)(Apache\s+Server\s+Status|Requests\s+currently\s+being\s+processed)',
        r'(?i)(Active\s+connections:\s*\d|server\s+accepts\s+handled\s+requests)',
        r'(?i)"status"\s*:\s*"(UP|DOWN)"\s*,\s*"(components|groups|details)"',
        r'(?i)("diskSpace"\s*:\s*\{|"db"\s*:\s*\{.*"status")',
    ],

    # ── Config files: require actual secret assignment syntax ────────────────
    # Words like 'key', 'host', 'token' on a webpage are NOT config findings
    "config_files": [
        r'(?im)^(DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|MYSQL_PASSWORD)\s*=\s*\S',
        r'(?im)^(APP_KEY|SECRET_KEY|API_KEY|JWT_SECRET)\s*=\s*\S',
        r"(?i)define\s*\(\s*['\"]DB_PASSWORD['\"]",
        r'(?i)["\']password["\']\s*:\s*["\'][^"\']{4,}["\']',
    ],

    # ── Backup files: real SQL dump syntax ───────────────────────────────────
    "backup_files": [
        r'(?i)INSERT\s+INTO\s+`?\w+`?\s*VALUES\s*\(',
        r'(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?\w',
        r'(?i)(mysqldump\s+\d+\.\d+|-- Dump completed on)',
    ],

    # ── Git exposure: OR logic, each pattern matches ONE specific git file ────
    # Fixes the globant.com false positive where HTML <head> matched (?i)HEAD
    # These patterns CANNOT appear in normal HTML pages:
    #   - A 40-char hex string followed by "refs/" is exclusively packed-refs
    #   - "[core]" on its own line is exclusively .git/config
    #   - "ref: refs/heads/" is exclusively .git/HEAD content
    "git_exposure": [
        r'(?m)^[0-9a-f]{40}\s+refs/',          # packed-refs: SHA40 + ref path
        r'(?m)^\[core\]\s*$',                   # .git/config: [core] section header
        r'(?m)^ref:\s*refs/heads/\S',           # .git/HEAD: ref pointer format
        r'(?m)^repositoryformatversion\s*=\s*\d',  # .git/config version field
    ],

    # ── Log files: require log-level keywords WITH timestamp — blocks JS date matches ──
    # Bare timestamp pattern matches minified JS (moment.js, analytics bundles).
    # Require the timestamp to appear WITH a log level keyword on the same line.
    "log_files": [
        # Timestamped log line with severity level — the combination is specific
        r'\[\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\]]*\]\s*(ERROR|WARNING|WARN|DEBUG|INFO|CRITICAL|FATAL)',
        # PHP stack trace — specific to error logs
        r'(?i)(Stack\s+trace:|Traceback\s+\(most\s+recent\s+call)',
        # SQL error — specific to PHP/Laravel/DB logs
        r'(?i)SQLSTATE\[',
        # Laravel/PHP namespace in error — backslash namespace format
        r'(?i)Illuminate\\(Database|Http|Auth)\\',
        # Apache/Nginx combined log format: IP date "method path" status bytes
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[[\d/A-Za-z:+ ]+\]\s+"(GET|POST|HEAD)',
    ],

    # ── SSH keys: BEGIN header is unmistakable and cannot appear in HTML ──────
    "ssh_keys": [
        r'-----BEGIN\s+(RSA |DSA |EC |OPENSSH )?PRIVATE\s+KEY-----',
        r'-----BEGIN\s+CERTIFICATE-----',
    ],

    # ── Package files: require JSON manifest structure ────────────────────────
    # "name":"..." alone matches ANY JSON API (user profiles, REST responses).
    # Must require EITHER "dependencies":{} (npm) or "require":{"php": (composer)
    # combined with version — these ONLY appear in real package manifests.
    "package_files": [
        r'"dependencies"\s*:\s*\{',                     # npm package.json
        r'"devDependencies"\s*:\s*\{',                  # npm dev deps
        r'"require"\s*:\s*\{\s*"php"\s*:',              # composer.json
        r'"require-dev"\s*:\s*\{',                      # composer dev
        r'"lockfileVersion"\s*:\s*\d',                  # package-lock.json
        r'"packages"\s*:\s*\{\s*""\s*:\s*\[',           # composer.lock root
    ],

    # ── DevOps files: docker-compose/Dockerfile specific syntax ──────────────
    # Removed: "services:$" alone — matches k8s, Ansible, custom YAML.
    # Require "services:" COMBINED with docker-compose-specific keys beneath it,
    # or Dockerfile instructions that are unambiguous.
    "devops_files": [
        # docker-compose: services block followed by image/build/ports child keys
        r'(?m)^services:\s*\n(\s+\S+:\s*\n)?\s+(image|build|ports|environment|volumes|depends_on)\s*:',
        # Dockerfile: FROM instruction is highly specific
        r'(?m)^FROM\s+([\w./:-]+)\s*(AS\s+\w+)?\s*$',
        # Dockerfile RUN/ENV/COPY/ARG — require at least one of these
        r'(?m)^(RUN|ENV|COPY|ARG|EXPOSE|ENTRYPOINT|CMD)\s+\S',
        # CI/DevOps credential vars embedded in compose/dockerfile
        r'(?im)(DOCKER_PASSWORD|REGISTRY_TOKEN|CI_TOKEN|VAULT_ADDR)\s*[=:]',
    ],

    # ── Server status: Apache/Nginx/Spring specific output format ────────────
    # Tightened: "status":"UP","components" is broad enough for Spring Actuator
    # specifically because "components" is Actuator-specific. Keep as-is but
    # add a note — this is a true positive for Actuator health endpoint.
    "server_status": [
        r'(?i)(Apache\s+Server\s+Status|Requests\s+currently\s+being\s+processed)',
        r'(?i)(Active\s+connections:\s*\d|server\s+accepts\s+handled\s+requests)',
        # Spring Actuator /health: "components" key is unique to Actuator format
        r'(?i)"status"\s*:\s*"(UP|DOWN|OUT_OF_SERVICE)"\s*,\s*"components"\s*:',
        # Spring Actuator /health with diskSpace or db components
        r'(?i)("diskSpace"\s*:\s*\{\s*"status"|"db"\s*:\s*\{\s*"status")',
    ],

    # ── API docs: Swagger/OpenAPI JSON document structure ────────────────────
    # "paths":{} alone matches ANY JSON API response — must require the swagger
    # or openapi version field that only appears in spec documents.
    "api_exposure": [
        r'"swagger"\s*:\s*"[23]\.',
        r'"openapi"\s*:\s*"[23]\.',
        r'"swaggerVersion"\s*:\s*"[12]\.',
        r'(?i)<title>[^<]*swagger\s*ui[^<]*</title>',
        r'(?i)Swagger\s+UI\s*[-–]',
    ],

    # ── WordPress: specific data-leaking WP responses ────────────────────────
    # NOT wp-login.php (that's normal). Only actually-leaking endpoints.
    "wordpress": [
        r'"id"\s*:\s*\d+\s*,\s*"name"\s*:\s*"[^"]+"\s*,\s*"url"\s*:',
        r'(?i)XML-RPC\s+server\s+accepts\s+POST\s+requests\s+only',
        r'(?i)<methodResponse>',
        r'(?i)"capabilities"\s*:\s*\{\s*"edit_posts"',
    ],

    # .env files use _looks_like_env() — no signatures needed here
    "env_files": [],

    # ── NEW modules ──────────────────────────────────────────────────────────

    # Cloud metadata: AWS/GCP/Azure IMDS responses have unique JSON structure.
    # STRICT: removed "token_type":"Bearer" — matches ANY OAuth API response.
    # AWS credentials file uses \n — requires re.DOTALL or (?s); use [\s\S] instead.
    "cloud_metadata": [
        r'"instanceId"\s*:\s*"i-[0-9a-f]{8,17}"',           # AWS EC2 instance ID
        r'"availabilityZone"\s*:\s*"[a-z]+-[a-z]+-\d[a-z]"',  # AWS AZ format
        r'"serviceAccounts"\s*:\s*\{',                        # GCP IMDS service accounts
        r'"access_token"\s*:\s*"ya29\.',                      # GCP OAuth token prefix (unique)
        r'"subscriptionId"\s*:\s*"[0-9a-f-]{36}"',           # Azure subscription UUID
        r'(?m)^\[default\][\s\S]{0,60}aws_access_key_id',    # AWS credentials file [default] section
        r'AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}',                # AWS access key ID prefixes
        r'"iamInstanceProfile"\s*:\s*\{',                    # AWS IAM instance profile (unique)
        r'"computeMetadata"\s*/\s*v[12]',                    # GCP metadata server path
    ],

    # Exposed secrets: credential file formats.
    # STRICT: removed generic "^password\s*=\s*\S{4,}" — too broad, matches
    # mysql.cnf, php.ini, configparser files, etc. Use only highly-specific formats.
    "exposed_secrets": [
        r'"type"\s*:\s*"service_account"',              # GCP service account JSON
        r'"private_key_id"\s*:\s*"[0-9a-f]{40}"',      # GCP private key ID (40-char hex)
        r'"client_email"\s*:\s*"[^@"]+@[^"]+\.iam\.gserviceaccount\.com"',  # GCP email format
        r'(?m)^machine\s+\S+\s+login\s+\S+\s+password\s+\S+',  # .netrc exact format
        r'AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}',           # AWS access key ID prefixes
        r'"sftp"\s*:\s*\{[^}]*"host"\s*:\s*"[^"]+"[^}]*"user"\s*:',  # Sublime SFTP JSON
        r'define_host\s*,\s*"[^"]+",\s*\d+',            # FTP credential format
        # Require BOTH private_key and project_id in the same JSON — unique to GCP SA
        r'"private_key"\s*:\s*"-----BEGIN (RSA |EC )?PRIVATE',
    ],

    # CI/CD: pipeline syntax unique to each system.
    # STRICT: avoid matching generic YAML. Require CI-specific keys or credentials.
    # Removed: "stages:$", "jobs:$", "steps:$" — too broad (any YAML).
    # Removed: "- deploy:" — matches Ansible task lists too.
    "cicd_exposure": [
        # GitHub Actions trigger block — unique two-line pattern
        r'(?m)^on:\s*\n\s+(push|pull_request|workflow_dispatch|release):',
        # Jenkinsfile declarative pipeline syntax — unique curly-brace agent block
        r'(?i)pipeline\s*\{\s*\n\s*agent\s+',
        # Explicit CI credential variable names (specific enough)
        r'(?i)(CI_TOKEN|DEPLOY_KEY|NPM_TOKEN|DOCKER_PASSWORD|REGISTRY_PASS|HEROKU_API_KEY)\s*:',
        # Cloud deploy commands embedded in CI scripts
        r'(?m)^\s+[-]\s+(aws ecr|docker push|kubectl apply|helm upgrade|gcloud deploy)',
        # Travis CI header — unique marker
        r'(?m)^language:\s*(node_js|python|ruby|php|go|java)\s*$',
        # CircleCI config version field — unique to CircleCI
        r'(?m)^version:\s*["\']?2\.[01]["\']?\s*\norbs:',
        # Bitbucket pipelines — unique structure
        r'(?m)^pipelines:\s*\n\s+(branches|default|pull-requests|custom):',
    ],

    # Kubernetes: k8s YAML manifest structure.
    # STRICT: require the apiVersion+kind combination which is unique to k8s.
    # Removed: "namespace:$", "image:\s*..." — too broad across YAML files.
    "kubernetes": [
        # apiVersion is the strongest single k8s indicator — no other YAML uses this
        r'(?m)^apiVersion:\s*(v1|apps/v1|batch/v1|rbac\.authorization\.k8s\.io/v1|networking\.k8s\.io/v1)',
        # kind: + k8s resource type — only valid in k8s manifests
        r'(?m)^kind:\s*(Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|ConfigMap|Secret|Ingress|Service|ServiceAccount|ClusterRole|Role|PersistentVolumeClaim)',
        # Secret/ConfigMap key reference — k8s-only syntax inside container specs
        r'(?i)(secretKeyRef|configMapKeyRef)\s*:',
        # k8s Secret data block with base64 values
        r'(?m)^(type:\s*kubernetes\.io/(tls|service-account-token|dockerconfigjson)|data:\s*\n\s+\S+:\s*[A-Za-z0-9+/=]{20,})',
    ],

    # Database exposure: config file formats
    # STRICT: avoid matching normal auth APIs, login forms, or any JSON with email/password.
    # "password":"..." alone matches every login form API. Must require DB-specific context.
    "database_exposure": [
        r'(?im)^bind-address\s*=\s*\S',                 # MySQL my.cnf — unique DB config key
        r'(?im)^(innodb_buffer_pool_size|max_allowed_packet)\s*=',  # MySQL-specific settings
        r'(?im)^(listen_addresses|max_connections|shared_buffers)\s*=',  # Postgres postgresql.conf
        r'(?im)^(requirepass|maxmemory|appendonly)\s+\S',  # Redis redis.conf
        r'(?i)(INSERT INTO users|INSERT INTO accounts|INSERT INTO customers)',  # SQL user dumps
        r'(?i)email,password\s*\n',                      # CSV header with email+password column
        r'(?m)^host\s+all\s+all\s+',                    # pg_hba.conf host ACL rule
        r'(?im)^(cluster\.name|network\.host)\s*:',     # Elasticsearch config
    ],
}
FP_MARKERS = [
    r'(?i)^#',                    # comment lines
    r'(?i)=\s*$',                 # empty value
    r'(?i)=\s*null\b',            # null value
    r'(?i)=\s*false\b',           # false value
    r'(?i)=\s*true\b',            # true value (standalone booleans are not secrets)
    r'(?i)=\s*your_',             # placeholder: your_key, your_secret etc.
    r'(?i)=\s*<',                 # placeholder: <value>, <TOKEN>
    r'(?i)=\s*\{',                # object placeholder
    r'(?i)=\s*\[',                # array placeholder
    r'(?i)_example\b',            # example suffix
    r'(?i)_placeholder\b',        # placeholder suffix
    r'(?i)(change.?me|changethis|=\s*change\w+)',  # change-me / changethis / change_value placeholders
    r'(?i)xxx+',                  # xxx placeholder
    r'(?i)=\s*enter.{0,20}here',  # "enter value here" placeholder
    r'(?i)=\s*replace.{0,20}this',# "replace this" placeholder
    r'(?i)=\s*replace.?me',        # REPLACE_ME / replace-me
    r'(?i)=\s*todo\b',            # TODO placeholder
    r'(?i)=\s*\*+\s*$',          # asterisks only (redacted display)
    r'(?i)=\s*(password|secret|root|admin|user|test|example|dummy|sample)\s*$',  # literal placeholder values
    r'(?i)your[\-_]',              # your-secret-key / your_secret variants
    r'(?i)some.?random',            # SomeRandomString / some_random_value
    r'(?i)example[_\-]',           # example_password / example-key
    r'(?i)^(login|username|password|user|email)\s*$',  # standalone words (not KEY=val)
]

# Pre-compiled for performance — avoids repeated re.compile() in hot paths
# FP_MARKERS: strip per-pattern (?i) flags, apply re.IGNORECASE globally.
# Joining patterns that each contain (?i) raises re.error on Python 3.6+:
#   "global flags not at the start of the expression"
# because only the FIRST sub-pattern in a joined OR may set global flags.
def _strip_inline_flags(pat: str) -> str:
    """Remove leading (?iflag) groups so patterns can be safely joined with |"""
    return re.sub(r"^\(\?[imsxaul]+\)", "", pat)

_FP_RE_COMPILED = re.compile(
    "|".join(_strip_inline_flags(p) for p in FP_MARKERS),
    re.IGNORECASE | re.MULTILINE
)
# SENSITIVE_PATTERNS: compiled individually so their own inline flags are safe
_SENS_RE_COMPILED = {cat: re.compile(pat) for cat, pat in SENSITIVE_PATTERNS.items()}

# (Pre-compiled regexes are defined below, after _strip_inline_flags is declared)

# Pre-compiled soft-404 / block-page detector
# Covers: custom 404 pages, CDN/WAF block pages that return HTTP 200,
# "Access Denied" responses from security middleware.
_SOFT_404_RE = re.compile(
    r'<title>[^<]*(404|not.?found|page.?not.?found|error|access.?denied|forbidden|blocked)[^<]*</title>'
    r'|(the page you (are looking for|requested) (could not be found|does not exist))'
    r'|(404\s*[-–—]\s*(not found|page not found|file not found))'
    r'|(\b404\s+not\s+found\b)'
    r'|(page\s+not\s+found\b)'
    r'|(this page (doesn.t|does not) exist)'
    r'|(sorry[,.]?\s+that page (doesn.t|does not) exist)'
    r'|(oops[.!]?\s+(something went wrong|page not found|we can.t find|couldn.t find))'
    r'|(oops[!.]+\s+we\s+couldn.t\s+find)'
    r'|(no\s+such\s+file\s+or\s+directory)'
    r'|(<h[12][^>]*>\s*(404|page\s+not\s+found|not\s+found)[^<]*</h[12]>)'
    # WAF/CDN block pages that return HTTP 200 but deny access
    r'|(access\s+denied[^<]{0,80}(cloudflare|firewall|waf|security|blocked))'
    r'|(your\s+(ip|request|access)\s+(has\s+been\s+blocked|is\s+not\s+allowed))'
    r'|(this\s+(request|page|site)\s+(has\s+been\s+blocked|is\s+(forbidden|restricted|not\s+accessible)))'
    r'|(<title>[^<]*(403|forbidden|access\s+denied)[^<]*</title>)'
    r'|(error\s+code[:\s]+403\b)',
    re.IGNORECASE
)

USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/121.0",
    "curl/7.88.1",
]


# ─── TARGET DEDUPLICATION ─────────────────────────────────────────────────────
def _dedup_targets(targets: list) -> "List[str]":
    """
    Deduplicate targets intelligently:
    - Treats http://x.com and https://x.com as the SAME host (keeps https)
    - Strips trailing slashes before comparing
    - Preserves first-occurrence order
    Real-world: crt.sh returns https://, a user's targets file has http://
    Without this the same site is scanned twice, doubling noise and load.
    """
    from urllib.parse import urlparse as _up
    seen: dict = {}  # lowercased netloc → canonical URL
    for raw in targets:
        url = raw.strip().rstrip("/")
        if not url:
            continue
        try:
            p = _up(url if "://" in url else "https://" + url)
            key = p.netloc.lower()
            if not key:
                continue
            if key not in seen:
                seen[key] = url
            elif url.startswith("https://") and seen[key].startswith("http://"):
                seen[key] = url  # upgrade plain http to https
        except Exception:
            seen.setdefault(url, url)
    return list(seen.values())


# ─── SAFE ARGS HELPER ─────────────────────────────────────────────────────────
def aget(args, attr: str, default=None):
    """Safe attribute access on any args object (argparse namespace or plain class)."""
    return getattr(args, attr, default)


# ─── SAFE PROMPT HELPERS ──────────────────────────────────────────────────────
def prompt_int(question: str, default: int, min_val: int = 1, max_val: int = 99999) -> int:
    """
    Ask for an integer with validation loop.
    Accepts:  '10', '10.0', '10.5' (truncated), '  10  '
    Rejects:  'abc', '', negative (if min_val > 0)
    """
    while True:
        raw = Prompt.ask(question, default=str(default)).strip()
        try:
            # Accept floats like '0.5' and truncate — user intent is clear
            val = int(float(raw))
            if min_val <= val <= max_val:
                return val
            console.print(f"  [red]  ✗ Enter a number between {min_val} and {max_val}[/red]")
        except (ValueError, OverflowError):
            console.print(f"  [red]  ✗ '{raw}' is not a valid number — try again[/red]")


def prompt_float(question: str, default: float, min_val: float = 0.0, max_val: float = 3600.0) -> float:
    """
    Ask for a float with validation loop.
    Accepts:  '0', '0.5', '1', '1.5', '2.0', '.5'
    Rejects:  'abc', 'half', negative values
    """
    while True:
        raw = Prompt.ask(question, default=str(default)).strip()
        # Allow common shorthand: '.5' → '0.5'
        if raw.startswith('.'):
            raw = '0' + raw
        try:
            val = float(raw)
            if min_val <= val <= max_val:
                return val
            console.print(f"  [red]  ✗ Enter a number between {min_val} and {max_val}[/red]")
        except (ValueError, OverflowError):
            console.print(f"  [red]  ✗ '{raw}' is not a valid number — try again (e.g. 0.5, 1, 2)[/red]")


# ─── DATA MODELS ──────────────────────────────────────────────────────────────
class ExposedEnv:
    def __init__(self, url: str, status_code: int, content_length: int, content_type: str):
        self.url            = url
        self.status_code    = status_code
        self.content_length = content_length
        self.content_type   = content_type
        self.raw_content    = ""
        self.findings: dict = {}
        self.risk_level     = "LOW"


class ExposedPage:
    """
    Represents any publicly accessible resource that should NOT be public.
    Covers phpMyAdmin, admin panels, debug pages, git repos, backups, etc.
    """
    def __init__(self, url: str, status_code: int, content_length: int,
                 module: str, label: str, evidence: List[str]):
        self.url            = url
        self.status_code    = status_code
        self.content_length = content_length
        self.module         = module   # key from SCAN_MODULES
        self.label          = label    # human label e.g. "phpMyAdmin / DB Admin"
        self.evidence       = evidence # matched signature lines / keywords
        self.risk_level     = "MEDIUM" # default; engine upgrades based on module
        self.raw_snippet    = ""       # first 500 chars of response


class ScanResult:
    def __init__(self, target: str):
        self.target          = target
        self.timestamp       = datetime.now(timezone.utc).isoformat()
        self.exposed_envs:  List[ExposedEnv]   = []
        self.exposed_pages: List[ExposedPage]  = []
        self.vuln_results:  list               = []   # VulnFinding objects
        self.ajax_surfaces: dict               = {}   # reachable AJAX paths
        self.xmlrpc:        Optional[dict]     = None # XML-RPC surface
        self.pma_scores:    list               = []   # phpMyAdmin session scores
        self.scan_status     = "pending"
        self.source          = "manual"  # manual | shodan | censys | crtsh | hackertarget | otx


# ─── DEFAULT ARGS ─────────────────────────────────────────────────────────────

# ─── VULNERABILITY MODULES ────────────────────────────────────────────────────
# RedHunter v1.0 — detection-only fingerprinting engine.
# Each module identifies WHETHER a vulnerability surface is present by reading
# publicly available server responses. No payloads are sent. Confirmed surfaces
# are reported with CVE, CVSS score, affected versions, and recommended tooling
# for the operator to use in a scoped authorized engagement.
# ──────────────────────────────────────────────────────────────────────────────

# ── WordPress plugin version fingerprint paths ────────────────────────────────
# Reading readme.txt / package.json from plugin directories is a normal HTTP GET
# — the server volunteers this information publicly.
WP_PLUGIN_FINGERPRINTS: dict = {
    # plugin_slug: (version_regex, paths_to_check)
    "powerpack-for-learndash": (
        r"(?i)Stable tag:\s*([\d.]+)",
        [
            "/wp-content/plugins/powerpack-for-learndash/readme.txt",
            "/wp-content/plugins/powerpack-addon-for-learndash/readme.txt",
        ],
    ),
    "drag-and-drop-multiple-file-upload-contact-form-7": (
        r"(?i)Stable tag:\s*([\d.]+)",
        ["/wp-content/plugins/drag-and-drop-multiple-file-upload-contact-form-7/readme.txt"],
    ),
    "reflex-gallery": (
        r"(?i)Stable tag:\s*([\d.]+)",
        ["/wp-content/plugins/reflex-gallery/readme.txt"],
    ),
    "wp-file-manager": (
        r"(?i)Stable tag:\s*([\d.]+)",
        ["/wp-content/plugins/wp-file-manager/readme.txt"],
    ),
    "wp-all-import": (
        r"(?i)Stable tag:\s*([\d.]+)",
        ["/wp-content/plugins/wp-all-import/readme.txt"],
    ),
    "essential-addons-for-elementor-lite": (
        r"(?i)Stable tag:\s*([\d.]+)",
        ["/wp-content/plugins/essential-addons-for-elementor-lite/readme.txt"],
    ),
    "wp-automatic": (
        r"(?i)Stable tag:\s*([\d.]+)",
        ["/wp-content/plugins/wp-automatic/readme.txt"],
    ),
    "backup-migration": (
        r"(?i)Stable tag:\s*([\d.]+)",
        ["/wp-content/plugins/backup-migration/readme.txt"],
    ),
    "gravityforms": (
        r"(?i)\$version\s*=\s*'([\d.]+)'",
        ["/wp-content/plugins/gravityforms/gravityforms.php"],
    ),
    "woocommerce": (
        r"(?i)Stable tag:\s*([\d.]+)",
        ["/wp-content/plugins/woocommerce/readme.txt"],
    ),
}

# ── CVE database keyed by (plugin_slug, operator, version_string) ─────────────
# operator: "lt" = vulnerable if installed_version < fixed_version
#            "lte" = vulnerable if installed_version <= fixed_version
# Source: public NVD / WPScan advisories — no private or unreleased data.
CVE_DATABASE: list = [
    {
        "plugin":      "powerpack-for-learndash",
        "cve":         "CVE-2026-2446",
        "cvss":        9.8,
        "severity":    "CRITICAL",
        "title":       "Unauthenticated Arbitrary Option Update",
        "fixed_in":    "1.3.0",
        "operator":    "lt",
        "description": (
            "The plugin registers an AJAX action reachable without authentication. "
            "An unauthenticated attacker can call learndash_save_class_data_ajax "
            "to write arbitrary WordPress options — including enabling user registration "
            "or escalating privileges by setting admin email."
        ),
        "affected_action": "learndash_save_class_data_ajax",
        "surface":     "wp-ajax-nopriv",
        "references":  ["https://www.wordfence.com/threat-intel/vulnerabilities/"],
        "recommend":   "Update plugin to ≥ 1.3.0. Verify via WPScan or Nuclei wp-plugin template.",
    },
    {
        "plugin":      "drag-and-drop-multiple-file-upload-contact-form-7",
        "cve":         "CVE-2026-3459",
        "cvss":        9.8,
        "severity":    "CRITICAL",
        "title":       "Unauthenticated Unrestricted File Upload",
        "fixed_in":    "1.3.8",
        "operator":    "lt",
        "description": (
            "The dnd_codedropz_upload AJAX action accepts file uploads without "
            "authentication. File type validation is client-side only. "
            "PHP files can be uploaded and executed as web shells."
        ),
        "affected_action": "dnd_codedropz_upload",
        "surface":     "wp-ajax-nopriv",
        "references":  ["https://nvd.nist.gov/vuln/detail/CVE-2026-3459"],
        "recommend":   "Update plugin immediately. Check uploads directory for existing .php files.",
    },
    {
        "plugin":      "reflex-gallery",
        "cve":         "N/A (Zero-Day)",
        "cvss":        9.8,
        "severity":    "CRITICAL",
        "title":       "Unauthenticated File Upload via Legacy FileUploader",
        "fixed_in":    "9999.0",   # no patch available
        "operator":    "lte",
        "description": (
            "The plugin ships a legacy PHP FileUploader at "
            "wp-content/plugins/reflex-gallery/admin/scripts/FileUploader/php.php "
            "which accepts arbitrary file uploads including PHP scripts via the "
            "qqfile parameter. The Year/Month query parameters control the upload path. "
            "No authentication is required."
        ),
        "affected_action": "FileUploader/php.php",
        "surface":     "direct-endpoint",
        "references":  [],
        "recommend":   "Deactivate/remove plugin. Audit upload directory for .php files immediately.",
    },
    {
        "plugin":      "wp-file-manager",
        "cve":         "CVE-2020-25213",
        "cvss":        9.8,
        "severity":    "CRITICAL",
        "title":       "Unauthenticated Remote Code Execution via elFinder",
        "fixed_in":    "6.9",
        "operator":    "lt",
        "description": (
            "WP File Manager < 6.9 exposes an unauthenticated elFinder connector "
            "endpoint. Attackers can upload PHP web shells and execute arbitrary code."
        ),
        "affected_action": "wp_file_manager",
        "surface":     "wp-ajax-nopriv",
        "references":  ["https://nvd.nist.gov/vuln/detail/CVE-2020-25213"],
        "recommend":   "Update to 6.9+. Immediately audit for malicious uploads.",
    },
    {
        "plugin":      "essential-addons-for-elementor-lite",
        "cve":         "CVE-2023-32243",
        "cvss":        9.8,
        "severity":    "CRITICAL",
        "title":       "Unauthenticated Privilege Escalation",
        "fixed_in":    "5.7.2",
        "operator":    "lt",
        "description": (
            "Password reset functionality allows privilege escalation to any user "
            "including administrator without authentication."
        ),
        "affected_action": "essential_addons_elementor",
        "surface":     "wp-ajax-nopriv",
        "references":  ["https://nvd.nist.gov/vuln/detail/CVE-2023-32243"],
        "recommend":   "Update to 5.7.2+. Rotate admin passwords.",
    },
    {
        "plugin":      "wp-automatic",
        "cve":         "CVE-2024-27956",
        "cvss":        9.9,
        "severity":    "CRITICAL",
        "title":       "Unauthenticated SQL Injection",
        "fixed_in":    "3.92.1",
        "operator":    "lt",
        "description": (
            "The plugin's CSV handler does not sanitize user-supplied input, "
            "allowing unauthenticated SQL injection to extract credentials."
        ),
        "affected_action": "csv2post",
        "surface":     "direct-endpoint",
        "references":  ["https://nvd.nist.gov/vuln/detail/CVE-2024-27956"],
        "recommend":   "Update immediately. Rotate database credentials.",
    },
    {
        "plugin":      "backup-migration",
        "cve":         "CVE-2023-6553",
        "cvss":        9.8,
        "severity":    "CRITICAL",
        "title":       "Unauthenticated Remote Code Execution",
        "fixed_in":    "1.3.8",
        "operator":    "lt",
        "description": (
            "PHP code injection via the content-dir parameter allows unauthenticated "
            "remote code execution."
        ),
        "affected_action": "backup-migration",
        "surface":     "direct-endpoint",
        "references":  ["https://nvd.nist.gov/vuln/detail/CVE-2023-6553"],
        "recommend":   "Update to 1.3.8+. Check for existing compromise indicators.",
    },
]

# ── AJAX surface detection paths ──────────────────────────────────────────────
# These endpoints are probed with GET to check reachability only.
# Confirming that admin-ajax.php returns HTTP 200 establishes the surface exists.
WP_AJAX_SURFACE_PATHS = [
    "/wp-admin/admin-ajax.php",
    "/wp-json/wp/v2/",
    "/xmlrpc.php",
    "/wp-content/plugins/reflex-gallery/admin/scripts/FileUploader/php.php",
]

# ── phpMyAdmin session quality heuristics ─────────────────────────────────────
# Checks whether a detected phpMyAdmin instance shows signs of an active or
# weak session — based on public cookie/response analysis.
PMA_SESSION_INDICATORS = [
    r"phpMyAdmin",
    r"pma_lang",
    r"pmaUser-1",
    r"pmaAuth-1",
    r"token=",
    r"db=",
    r"table=",
    r"Contains\s+database\s+names",
    r"SQL\s+interface",
]

# ── Version comparison utility ────────────────────────────────────────────────
def _version_tuple(v: str):
    """Convert version string to comparable tuple. Non-numeric parts become 0."""
    try:
        return tuple(int(x) for x in re.sub(r"[^\d.]", "", str(v)).split(".") if x)
    except Exception:
        return (0,)

def _is_vulnerable(installed: str, fixed_in: str, operator: str) -> bool:
    """Return True if installed version is in the vulnerable range."""
    try:
        iv = _version_tuple(installed)
        fv = _version_tuple(fixed_in)
        if operator == "lt":
            return iv < fv
        if operator == "lte":
            # "no patch" sentinel: 9999.0 means always vulnerable
            if fv == (9999, 0):
                return True
            return iv <= fv
        return False
    except Exception:
        return False


# ─── VULN FINDING DATA MODEL ─────────────────────────────────────────────────
class VulnFinding:
    """A confirmed vulnerability surface detected on a target."""
    def __init__(self, target: str, plugin: str, installed_version: str,
                 cve_entry: dict, surface_url: str, evidence: str):
        self.target            = target
        self.plugin            = plugin
        self.installed_version = installed_version
        self.cve               = cve_entry.get("cve", "N/A")
        self.cvss              = cve_entry.get("cvss", 0.0)
        self.severity          = cve_entry.get("severity", "UNKNOWN")
        self.title             = cve_entry.get("title", "")
        self.description       = cve_entry.get("description", "")
        self.affected_action   = cve_entry.get("affected_action", "")
        self.surface           = cve_entry.get("surface", "")
        self.fixed_in          = cve_entry.get("fixed_in", "N/A")
        self.references        = cve_entry.get("references", [])
        self.recommend         = cve_entry.get("recommend", "")
        self.surface_url       = surface_url
        self.evidence          = evidence
        self.timestamp         = datetime.now(timezone.utc).isoformat()


# ─── VULNERABILITY SCANNER ────────────────────────────────────────────────────
class VulnScanner:
    """
    Detection-only vulnerability fingerprinting engine.

    Sends normal read-only HTTP GETs to publicly accessible paths to:
      1. Detect installed WordPress plugin versions from readme.txt
      2. Match installed versions against CVE_DATABASE
      3. Verify that vulnerable AJAX/upload surfaces are reachable (HTTP 200)
      4. Score phpMyAdmin session quality from response headers/body
      5. Detect XML-RPC availability (brute-force surface)

    No exploit payloads are sent. Confirmation of exploitability requires
    authorized manual testing or dedicated tooling (Nuclei, WPScan, Burp).
    """

    def __init__(self, args: "DefaultArgs", session_factory):
        self.args            = args
        self._session_factory = session_factory   # callable → requests.Session
        self.findings: List[VulnFinding] = []
        self.lock = threading.Lock()

    def _get(self, url: str, timeout: int = 8) -> Optional[str]:
        """GET url, return text body or None on any error."""
        try:
            sess = self._session_factory()
            r = sess.get(url, timeout=(4, timeout), allow_redirects=False,
                         verify=False,
                         headers={"User-Agent": "Mozilla/5.0 (compatible; security-scanner/1.0)"})
            r.close()
            if r.status_code == 200 and r.content:
                return r.text
            return None
        except Exception:
            return None

    def _head_status(self, url: str) -> int:
        """Return HTTP status for url via HEAD (fast reachability check)."""
        try:
            sess = self._session_factory()
            r = sess.head(url, timeout=(4, 6), allow_redirects=False,
                          verify=False,
                          headers={"User-Agent": "Mozilla/5.0 (compatible; security-scanner/1.0)"})
            r.close()
            return r.status_code
        except Exception:
            return 0

    def _extract_version(self, body: str, pattern: str) -> Optional[str]:
        """Extract version string from body using pattern."""
        try:
            m = re.search(pattern, body, re.IGNORECASE | re.MULTILINE)
            return m.group(1).strip() if m else None
        except Exception:
            return None

    def scan_plugins(self, target: str) -> List[VulnFinding]:
        """
        Fingerprint installed WordPress plugins and match against CVE_DATABASE.
        Returns list of VulnFinding for each confirmed vulnerable plugin.
        """
        found: List[VulnFinding] = []

        for slug, (ver_pattern, paths) in WP_PLUGIN_FINGERPRINTS.items():
            installed_version = None
            hit_path = None
            body = None

            for path in paths:
                url = target.rstrip("/") + path
                body = self._get(url)
                if body:
                    installed_version = self._extract_version(body, ver_pattern)
                    if installed_version:
                        hit_path = url
                        break

            if not installed_version:
                continue  # plugin not detected or no readable version

            # Match against every CVE entry for this plugin
            for cve_entry in CVE_DATABASE:
                if cve_entry["plugin"] != slug:
                    continue
                if not _is_vulnerable(installed_version, cve_entry["fixed_in"],
                                      cve_entry["operator"]):
                    continue

                # Plugin is present and vulnerable — verify surface reachability
                surface_url  = ""
                surface_reachable = False

                if cve_entry["surface"] == "wp-ajax-nopriv":
                    ajax_url = target.rstrip("/") + "/wp-admin/admin-ajax.php"
                    status   = self._head_status(ajax_url)
                    surface_reachable = (status == 200)
                    surface_url = ajax_url if surface_reachable else ""

                elif cve_entry["surface"] == "direct-endpoint":
                    # For direct endpoints, the readme path proves the plugin is
                    # installed; the endpoint path may differ per plugin.
                    for ep_path in [
                        "/wp-content/plugins/reflex-gallery/admin/scripts/FileUploader/php.php",
                        "/wp-content/plugins/backup-migration/index.php",
                    ]:
                        ep_url  = target.rstrip("/") + ep_path
                        ep_stat = self._head_status(ep_url)
                        if ep_stat in (200, 405):
                            surface_url       = ep_url
                            surface_reachable = True
                            break

                evidence = (
                    f"Plugin: {slug} v{installed_version} "
                    f"(vulnerable < {cve_entry['fixed_in']}) "
                    f"via {hit_path}"
                )
                if surface_reachable:
                    evidence += f" | Surface reachable: {surface_url}"

                vf = VulnFinding(
                    target=target,
                    plugin=slug,
                    installed_version=installed_version,
                    cve_entry=cve_entry,
                    surface_url=surface_url,
                    evidence=evidence,
                )
                found.append(vf)

        return found

    def scan_ajax_surfaces(self, target: str) -> dict:
        """
        Check which WordPress AJAX / upload surfaces are reachable.
        Returns dict of path → status_code for operator awareness.
        """
        results = {}
        for path in WP_AJAX_SURFACE_PATHS:
            url    = target.rstrip("/") + path
            status = self._head_status(url)
            if status in (200, 405):
                results[path] = status
        return results

    def score_phpmyadmin(self, target: str, page_body: Optional[str]) -> Optional[dict]:
        """
        Analyse a detected phpMyAdmin page for session quality indicators.
        Returns a score dict if indicators present, None if not a PMA page.
        """
        if not page_body:
            return None
        body_lower = page_body[:8000].lower()
        if "phpmyadmin" not in body_lower and "pma" not in body_lower:
            return None

        indicators_found = []
        for pattern in PMA_SESSION_INDICATORS:
            try:
                if re.search(pattern, page_body, re.IGNORECASE):
                    indicators_found.append(pattern)
            except Exception:
                pass

        score = len(indicators_found) * 2  # 2 points per indicator

        # Bonus: authenticated interface signs
        if re.search(r"(db=|table=|sql=|index\.php\?route)", page_body, re.IGNORECASE):
            score += 5
        if len(page_body) > 20_000:
            score += 3   # large response = likely rendered authenticated view

        return {
            "score":      score,
            "indicators": indicators_found,
            "large_body": len(page_body) > 20_000,
            "auth_signs": bool(re.search(r"(db=|table=|sql=)", page_body, re.IGNORECASE)),
            "risk":       "CRITICAL" if score >= 8 else "HIGH" if score >= 4 else "MEDIUM",
        }

    def scan_xmlrpc(self, target: str) -> Optional[dict]:
        """
        Detect whether XML-RPC is enabled and responsive.
        XML-RPC enabled = brute-force surface; multicall method = amplification.
        Detection only — no authentication attempts made.
        """
        url  = target.rstrip("/") + "/xmlrpc.php"
        body = self._get(url)
        if not body:
            return None
        if not re.search(r"XML-RPC|xmlrpc|methodResponse", body, re.IGNORECASE):
            return None
        multicall = bool(re.search(r"system\.multicall|listMethods", body, re.IGNORECASE))
        return {
            "url":       url,
            "multicall": multicall,
            "risk":      "HIGH",
            "note":      (
                "XML-RPC active. Brute-force surface confirmed. "
                + ("system.multicall available — amplification possible." if multicall else "")
            ),
        }

    def run(self, target: str) -> dict:
        """
        Run all vuln detection checks against a single target.
        Returns structured dict of all findings.
        """
        return {
            "target":        target,
            "vuln_findings": self.scan_plugins(target),
            "ajax_surfaces": self.scan_ajax_surfaces(target),
            "xmlrpc":        self.scan_xmlrpc(target),
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        }

class DefaultArgs:
    """
    Single place that defines every attribute with a safe default.
    Both the wizard and argparse CLI populate an instance of this,
    so the engine/reporter never encounter AttributeError.
    """
    def __init__(self):
        # Targets
        self.url: Optional[str]       = None
        self.file: Optional[str]      = None
        # Discovery
        self.discover: List[str]      = []
        self.shodan_key: Optional[str]= None
        self.shodan_query: List[str]  = []
        self.shodan_pages: int        = 1
        self.censys_id: Optional[str] = None
        self.censys_secret: Optional[str] = None
        self.censys_query: List[str]  = []
        self.use_crtsh: bool          = True
        self.use_hackertarget: bool   = True
        self.use_otx: bool            = True
        # Internal discovery query lists (wizard uses these)
        self._shodan_queries: List[str]  = []
        self._censys_queries: List[str]  = []
        # Scan
        self.threads: int             = 25
        self.timeout: int             = 10
        self.path_workers: int        = 20   # parallel path workers per target
        self.delay: float             = 0.0
        self.proxy: Optional[str]     = None
        self.aggressive: bool         = False
        self.extra_paths: List[str]   = []
        self.headers: List[str]       = []
        # Telegram
        self.tg_token: Optional[str]  = None
        self.tg_chat: Optional[str]   = None
        # Scheduler
        self.schedule: Optional[float]= None
        # Output
        self.output: str              = "./reports"
        self.json: bool               = False
        self.txt: bool                = False
        self.html: bool               = False
        self.all_reports: bool        = False
        self.redact: bool             = False
        self.show_content: bool       = False
        self.history: bool            = False
        self.verbose: bool            = False
        self.quiet: bool              = False
        # Vulnerability scanning
        self.vuln_scan: bool          = False
        self.vuln_only: bool          = False


def merge_argparse(parsed) -> DefaultArgs:
    """Overlay an argparse Namespace onto DefaultArgs so every attr is guaranteed."""
    cfg = DefaultArgs()
    for key, val in vars(parsed).items():
        # argparse stores None for unset optional args — keep DefaultArgs default in that case
        if val is not None:
            setattr(cfg, key, val)
        # For boolean flags argparse returns False, not None — always honour those
        if isinstance(val, bool):
            setattr(cfg, key, val)
    # Derived flags from --no-X args
    cfg.use_crtsh        = not getattr(parsed, "no_crtsh",        False)
    cfg.use_hackertarget = not getattr(parsed, "no_hackertarget", False)
    cfg.use_otx          = not getattr(parsed, "no_otx",          False)
    # Derive CLI discovery query lists into the internal names the engine uses
    cfg._shodan_queries  = list(getattr(parsed, "shodan_query", None) or [])
    cfg._censys_queries  = list(getattr(parsed, "censys_query", None) or [])
    if cfg.all_reports:
        cfg.json = cfg.txt = cfg.html = True
    # vuln flags: argparse uses underscores, CLI uses hyphens
    if getattr(parsed, "vuln_scan", False):
        cfg.vuln_scan = True
    if getattr(parsed, "vuln_only", False):
        cfg.vuln_only = True
    return cfg


# ─── STATE DATABASE ───────────────────────────────────────────────────────────
class StateDB:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        self.lock    = threading.Lock()
        self.conn    = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=10000")
        self._init()

    def _init(self):
        with self.lock:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS seen_findings (
                    fingerprint TEXT PRIMARY KEY,
                    url         TEXT NOT NULL,
                    risk_level  TEXT NOT NULL,
                    categories  TEXT NOT NULL,
                    kind        TEXT NOT NULL DEFAULT 'env',
                    first_seen  TEXT NOT NULL,
                    last_seen   TEXT NOT NULL
                )
            """)
            # Migrate existing DBs that don't have the kind column yet
            try:
                self.conn.execute("ALTER TABLE seen_findings ADD COLUMN kind TEXT NOT NULL DEFAULT 'env'")
            except Exception:
                pass  # Column already exists
            self.conn.commit()

    def _fp(self, env: ExposedEnv) -> str:
        raw = env.url + "|" + "|".join(sorted(env.findings.keys()))
        return hashlib.sha256(raw.encode()).hexdigest()

    def mark_seen_atomic(self, env: ExposedEnv) -> bool:
        """
        Atomically insert the finding and return True if it was NEW.
        Uses INSERT OR IGNORE so that the first thread to write wins.
        Checking rowcount inside the same lock eliminates the race condition
        where two threads both call is_new()→True then both fire Telegram alerts.
        """
        fp   = self._fp(env)
        now  = datetime.now(timezone.utc).isoformat()
        cats = ",".join(env.findings.keys()) or "exposed"
        with self.lock:
            cur = self.conn.execute("""
                INSERT OR IGNORE INTO seen_findings
                    (fingerprint, url, risk_level, categories, kind, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 'env', ?, ?)
            """, (fp, env.url, env.risk_level, cats, now, now))
            if cur.rowcount == 0:
                # Row already existed — update last_seen only
                self.conn.execute(
                    "UPDATE seen_findings SET last_seen=? WHERE fingerprint=?", (now, fp)
                )
            self.conn.commit()
            return cur.rowcount > 0  # True = new finding, False = already known

    def get_history(self) -> list:
        with self.lock:
            return self.conn.execute(
                "SELECT url,risk_level,categories,kind,first_seen,last_seen "
                "FROM seen_findings ORDER BY first_seen DESC"
            ).fetchall()

    def _fp_page(self, page) -> str:
        raw = page.url + "|page|" + page.module
        return hashlib.sha256(raw.encode()).hexdigest()

    def mark_seen_page_atomic(self, page) -> bool:
        """Atomically record a page finding. Returns True if it was new."""
        fp  = self._fp_page(page)
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            cur = self.conn.execute("""
                INSERT OR IGNORE INTO seen_findings
                    (fingerprint, url, risk_level, categories, kind, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 'page', ?, ?)
            """, (fp, page.url, page.risk_level, page.label, now, now))
            if cur.rowcount == 0:
                self.conn.execute(
                    "UPDATE seen_findings SET last_seen=? WHERE fingerprint=?", (now, fp)
                )
            self.conn.commit()
            return cur.rowcount > 0

    def mark_seen_vuln_atomic(self, vf: "VulnFinding") -> bool:
        """
        Atomically record a vuln finding. Returns True if it was NEW.
        Fingerprint = target + plugin + cve — ensures each CVE fires once per
        target per monitoring cycle (avoids alert fatigue on repeated scans).
        """
        raw = f"{vf.target}|vuln|{vf.plugin}|{vf.cve}"
        fp  = hashlib.sha256(raw.encode()).hexdigest()
        now = datetime.now(timezone.utc).isoformat()
        with self.lock:
            cur = self.conn.execute("""
                INSERT OR IGNORE INTO seen_findings
                    (fingerprint, url, risk_level, categories, kind, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 'vuln', ?, ?)
            """, (fp, vf.target, vf.severity, f"{vf.cve} — {vf.plugin}", now, now))
            if cur.rowcount == 0:
                self.conn.execute(
                    "UPDATE seen_findings SET last_seen=? WHERE fingerprint=?", (now, fp)
                )
            self.conn.commit()
            return cur.rowcount > 0

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ─── ASSET DISCOVERY ──────────────────────────────────────────────────────────
class AssetDiscovery:
    def __init__(self, args: DefaultArgs):
        self.args = args

    def _hdr(self) -> dict:
        return {"User-Agent": random.choice(USER_AGENTS)}

    def _norm_host(self, host: str, port: int = 443) -> str:
        scheme = "https" if port in (443, 8443) else "http"
        if port in (80, 443):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    # ── Shodan ────────────────────────────────────────────────────────────────
    def shodan_search(self, query: str) -> List[str]:
        if not self.args.shodan_key:
            console.print("[yellow]  [!] Shodan key not set — skipping.[/yellow]")
            return []
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ Shodan:[/cyan] {query}")
            for page in range(1, self.args.shodan_pages + 1):
                resp = requests.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": self.args.shodan_key, "query": query,
                            "page": page, "minify": True},
                    headers=self._hdr(), timeout=20
                )
                if resp.status_code == 401:
                    console.print("[red]  [!] Shodan: Invalid API key.[/red]")
                    break
                if resp.status_code != 200:
                    console.print(f"[red]  [!] Shodan HTTP {resp.status_code}[/red]")
                    break
                matches = resp.json().get("matches", [])
                if not matches:
                    break
                for m in matches:
                    port = m.get("port", 80)
                    for h in m.get("hostnames", []):
                        targets.append(self._norm_host(h, port))
                    ip = m.get("ip_str", "")
                    if ip and not m.get("hostnames"):
                        targets.append(self._norm_host(ip, port))
                console.print(f"    [dim]Page {page}: {len(matches)} results[/dim]")
                time.sleep(1)
        except Exception as e:
            console.print(f"[red]  [!] Shodan: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ Shodan: {len(unique)} targets[/green]")
        return unique

    # ── Censys ────────────────────────────────────────────────────────────────
    def censys_search(self, query: str) -> List[str]:
        if not (self.args.censys_id and self.args.censys_secret):
            console.print("[yellow]  [!] Censys credentials not set — skipping.[/yellow]")
            return []
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ Censys:[/cyan] {query}")
            resp = requests.get(
                "https://search.censys.io/api/v2/hosts/search",
                params={"q": query, "per_page": 100},
                headers={"Accept": "application/json", **self._hdr()},
                auth=(self.args.censys_id, self.args.censys_secret),
                timeout=20
            )
            if resp.status_code == 401:
                console.print("[red]  [!] Censys: Invalid credentials.[/red]")
                return []
            if resp.status_code != 200:
                console.print(f"[red]  [!] Censys HTTP {resp.status_code}[/red]")
                return []
            for hit in resp.json().get("result", {}).get("hits", []):
                name = hit.get("name", "") or hit.get("ip", "")
                if name:
                    targets.append(f"https://{name}")
        except Exception as e:
            console.print(f"[red]  [!] Censys: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ Censys: {len(unique)} targets[/green]")
        return unique

    # ── crt.sh ────────────────────────────────────────────────────────────────
    def crtsh_search(self, domain: str) -> List[str]:
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ crt.sh:[/cyan] *.{domain}")
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                headers=self._hdr(), timeout=30
            )
            if resp.status_code != 200:
                console.print(f"[yellow]  [!] crt.sh HTTP {resp.status_code}[/yellow]")
                return []
            seen: set = set()
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name and "." in name and name not in seen:
                        seen.add(name)
                        targets.append(f"https://{name}")
        except Exception as e:
            console.print(f"[red]  [!] crt.sh: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ crt.sh: {len(unique)} subdomains[/green]")
        return unique

    # ── HackerTarget ──────────────────────────────────────────────────────────
    def hackertarget_search(self, domain: str) -> List[str]:
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ HackerTarget:[/cyan] {domain}")
            resp = requests.get(
                f"https://api.hackertarget.com/hostsearch/?q={domain}",
                headers=self._hdr(), timeout=20
            )
            if resp.status_code != 200:
                console.print(f"[yellow]  [!] HackerTarget HTTP {resp.status_code}[/yellow]")
                return []
            text = resp.text.strip()
            if "error" in text.lower() or not text:
                console.print(f"[yellow]  [!] HackerTarget: {text[:80]}[/yellow]")
                return []
            for line in text.splitlines():
                if "," in line:
                    name = line.split(",", 1)[0].strip()
                    if name:
                        targets.append(f"https://{name}")
        except Exception as e:
            console.print(f"[red]  [!] HackerTarget: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ HackerTarget: {len(unique)} subdomains[/green]")
        return unique

    # ── AlienVault OTX ────────────────────────────────────────────────────────
    def otx_search(self, domain: str) -> List[str]:
        targets: List[str] = []
        try:
            console.print(f"  [cyan]→ AlienVault OTX:[/cyan] {domain}")
            resp = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                headers=self._hdr(), timeout=20
            )
            if resp.status_code != 200:
                return []
            for rec in resp.json().get("passive_dns", []):
                h = rec.get("hostname", "").strip()
                if h:
                    targets.append(f"https://{h}")
        except Exception as e:
            console.print(f"[red]  [!] OTX: {e}[/red]")
        unique = list(set(targets))
        console.print(f"  [green]✔ OTX: {len(unique)} passive DNS records[/green]")
        return unique

    def discover_all(self, domains: List[str] = None,
                     shodan_queries: List[str] = None,
                     censys_queries: List[str] = None) -> List[str]:
        all_targets: List[str] = []
        console.print()
        console.print(Panel("[bold cyan]◉ Asset Discovery Phase[/bold cyan]", border_style="cyan"))

        for q in (shodan_queries or []):
            all_targets += self.shodan_search(q)

        for q in (censys_queries or []):
            all_targets += self.censys_search(q)

        for domain in (domains or []):
            domain = domain.strip().replace("https://", "").replace("http://", "").split("/")[0]
            if not domain:
                continue
            if self.args.use_crtsh:
                all_targets += self.crtsh_search(domain)
            if self.args.use_hackertarget:
                all_targets += self.hackertarget_search(domain)
            if self.args.use_otx:
                all_targets += self.otx_search(domain)

        deduped = list(set(all_targets))
        console.print(f"\n  [bold green]◉ Discovery complete — {len(deduped)} unique assets[/bold green]\n")
        return deduped


# ─── TELEGRAM NOTIFIER ────────────────────────────────────────────────────────
class TelegramNotifier:
    # Telegram HTML mode only allows: <b> <i> <code> <pre> <a> <s> <u>
    # All user-supplied strings MUST be escaped before insertion.
    # Max message length: 4096 chars — anything over is silently rejected by Telegram.
    _TG_MAX_LEN   = 4000   # 4096 minus safety margin for footer
    _TG_RATE_DELAY = 0.05  # 50ms between sends = max 20 msg/s (Telegram limit: 30/s)

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token  = bot_token
        self.chat_id    = chat_id
        self._base      = f"https://api.telegram.org/bot{bot_token}"
        self._last_send = 0.0   # monotonic time of last successful send
        self._lock      = threading.Lock()  # serialize rate-limit check

    @staticmethod
    def _e(text: str) -> str:
        """
        HTML-escape a string for safe insertion into Telegram HTML messages.
        Telegram HTML mode requires & < > to be escaped.
        Called on EVERY user-supplied value before it enters a message string.
        """
        return (str(text)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))

    def _send(self, text: str) -> bool:
        """
        Send a single Telegram message. Thread-safe, rate-limited.
        Error logging goes to stderr — NOT the Rich console — because Rich is
        not thread-safe when called from a background thread during Progress rendering.
        """
        # Enforce rate limit — Telegram allows ~30 msg/s, we use 20/s max
        with self._lock:
            elapsed = time.monotonic() - self._last_send
            if elapsed < self._TG_RATE_DELAY:
                time.sleep(self._TG_RATE_DELAY - elapsed)

        # Hard length guard — Telegram silently drops messages over 4096 chars
        if len(text) > self._TG_MAX_LEN:
            text = text[:self._TG_MAX_LEN] + "\n<i>… [message truncated]</i>"

        try:
            resp = requests.post(
                f"{self._base}/sendMessage",
                json={"chat_id": self.chat_id, "text": text, "parse_mode": "HTML"},
                timeout=15
            )
            with self._lock:
                self._last_send = time.monotonic()
            if resp.status_code == 200:
                return True
            # Log failure to stderr (safe from any thread, doesn't touch Rich)
            import sys as _sys
            print(
                f"[RedHunter] Telegram HTTP {resp.status_code}: {resp.text[:120]}",
                file=_sys.stderr
            )
            return False
        except requests.exceptions.ConnectionError:
            import sys as _sys
            print("[RedHunter] Telegram: network unreachable.", file=_sys.stderr)
        except requests.exceptions.Timeout:
            import sys as _sys
            print("[RedHunter] Telegram: request timed out.", file=_sys.stderr)
        except Exception as e:
            import sys as _sys
            print(f"[RedHunter] Telegram error: {e}", file=_sys.stderr)
        return False

    def send_finding(self, env: "ExposedEnv", target: str, is_new: bool = True) -> bool:
        emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(env.risk_level, "⚪")
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        badge = "🆕 <b>NEW FINDING</b>\n" if is_new else "🔄 <b>RE-SCAN MATCH</b>\n"
        env_context_map = {
            "CRITICAL": "Real credentials/keys confirmed — attacker can use these directly.",
            "HIGH":     "Payment or mail credentials exposed — financial or communication risk.",
            "MEDIUM":   "General secrets present — lower impact but still sensitive.",
            "LOW":      "File accessible but no sensitive keywords matched — review manually.",
        }
        env_context = env_context_map.get(env.risk_level, "")
        if env.findings:
            cats = "\n".join(f"  • <code>{self._e(c)}</code>" for c in env.findings.keys())
        else:
            cats = "  • <i>No sensitive keywords matched</i>"
        msg = (
            f"{badge}"
            f"{emoji} <b>.env Exposed — {self._e(env.risk_level)}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 <b>Target:</b> <code>{self._e(target)}</code>\n"
            f"🔗 <b>URL:</b> <code>{self._e(env.url)}</code>\n"
            f"📊 <b>HTTP:</b> {self._e(env.status_code)}  |  📏 <b>Size:</b> {self._e(env.content_length)}B\n"
            f"⏱ <b>Found at:</b> {now_ts}\n"
            f"\n{emoji} <b>Risk [{self._e(env.risk_level)}]:</b> <i>{self._e(env_context)}</i>\n"
            f"\n🔑 <b>Secrets Detected:</b>\n{cats}\n"
            f"\n<i>RedHunter v{VERSION} | {AUTHOR} | {TG_HANDLE}</i>"
        )
        return self._send(msg)

    def send_summary(self, stats: dict) -> bool:
        exposed   = stats.get("exposed", 0)
        pages     = stats.get("pages_found", 0)
        critical  = stats.get("critical", 0)
        new_finds = stats.get("new_findings", 0)
        if critical > 0:
            headline = f"🔴 <b>CRITICAL FINDINGS — {critical} critical items</b>"
        elif new_finds > 0:
            headline = f"⚠️ <b>{new_finds} new finding(s) — review required</b>"
        else:
            headline = "✅ <b>Scan complete — no new findings</b>"
        msg = (
            f"📋 <b>RedHunter — Scan Complete</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"{headline}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 Targets Scanned : <b>{stats.get('scanned',0)}</b>\n"
            f"🔌 Unreachable      : <b>{stats.get('unreachable',0)}</b>\n"
            f"🚨 .env Exposed    : <b>{exposed}</b>\n"
            f"🌐 Pages Exposed   : <b>{pages}</b>\n"
            f"🔴 Critical        : <b>{critical}</b>\n"
            f"🆕 New Findings    : <b>{new_finds}</b>\n"
            f"🐛 Vulns Found     : <b>{stats.get('vulns_found', 0)}</b>\n"
            f"💀 Vuln Critical   : <b>{stats.get('vuln_critical', 0)}</b>\n"
            f"🕐 Completed       : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"\n<i>RedHunter v{VERSION} | {AUTHOR} | {TG_HANDLE}</i>"
        )
        return self._send(msg)

    def send_page_finding(self, page: "ExposedPage", target: str) -> bool:
        emoji  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(page.risk_level, "⚪")
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        # Evidence lines come from raw HTTP responses — MUST be escaped
        ev = "\n".join(
            f"  • <code>{self._e(e[:100])}</code>" for e in page.evidence[:4]
        ) or "  • <i>Confirmed accessible</i>"
        context_map = {
            "CRITICAL": ("🚨 URGENT",   "Credentials or sensitive data directly readable — no authentication required."),
            "HIGH":     ("⚠️ HIGH",     "Sensitive structure exposed — source code, configs or secrets likely present."),
            "MEDIUM":   ("🔵 MEDIUM",   "Login interface publicly reachable — attacker still needs valid credentials."),
            "LOW":      ("ℹ️ INFO",     "Version or schema disclosure only — useful for attacker reconnaissance."),
        }
        sev_label, context = context_map.get(page.risk_level, ("", ""))
        msg = (
            f"🆕 <b>NEW FINDING — {self._e(sev_label)}</b>\n"
            f"{emoji} <b>{self._e(page.label)}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 <b>Target:</b> <code>{self._e(target)}</code>\n"
            f"🔗 <b>URL:</b> <code>{self._e(page.url)}</code>\n"
            f"📊 <b>HTTP:</b> {self._e(page.status_code)}  |  📏 <b>Size:</b> {self._e(page.content_length)}B\n"
            f"⏱ <b>Found at:</b> {now_ts}\n"
            f"\n{emoji} <b>Risk [{self._e(page.risk_level)}]:</b> <i>{self._e(context)}</i>\n"
            f"\n🔍 <b>Evidence:</b>\n{ev}\n"
            f"\n<i>RedHunter v{VERSION} | {AUTHOR} | {TG_HANDLE}</i>"
        )
        return self._send(msg)

    def send_vuln_finding(self, vf: "VulnFinding") -> bool:
        """Send Telegram alert for a confirmed vulnerable plugin surface."""
        emoji  = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(vf.severity, "⚪")
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        refs   = "\n".join(f"  • {self._e(r)}" for r in vf.references[:3]) or "  • No public references"
        surface_line = (
            f"\n🔌 <b>Surface URL:</b> <code>{self._e(vf.surface_url)}</code>"
            if vf.surface_url else ""
        )
        # All dynamic content escaped — descriptions often contain "<" (e.g. "version < 6.9")
        msg = (
            f"🆕 <b>VULNERABILITY DETECTED</b>\n"
            f"{emoji} <b>{self._e(vf.severity)} — {self._e(vf.cve)}</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"🎯 <b>Target:</b> <code>{self._e(vf.target)}</code>\n"
            f"🔌 <b>Plugin:</b> <code>{self._e(vf.plugin)}</code>\n"
            f"📦 <b>Installed:</b> v{self._e(vf.installed_version)}  →  "
            f"<b>Fixed in:</b> v{self._e(vf.fixed_in)}\n"
            f"📊 <b>CVSS:</b> {self._e(vf.cvss)}  |  🏷 <b>Surface:</b> {self._e(vf.surface)}\n"
            f"⏱ <b>Detected:</b> {now_ts}\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"📋 <b>Title:</b> {self._e(vf.title)}\n"
            f"\n📝 <b>Description:</b>\n<i>{self._e(vf.description[:350])}</i>\n"
            f"{surface_line}\n"
            f"\n✅ <b>Recommended Action:</b>\n<i>{self._e(vf.recommend)}</i>\n"
            f"\n🔗 <b>References:</b>\n{refs}\n"
            f"\n<i>RedHunter v{VERSION} | {AUTHOR} | {TG_HANDLE}</i>"
        )
        return self._send(msg)

    def test_connection(self) -> bool:
        return self._send(
            f"✅ <b>RedHunter v{VERSION}</b> — Telegram integration active.\n"
            f"Authored by {self._e(AUTHOR)} | {self._e(TG_HANDLE)}"
        )


# ─── SCAN ENGINE ──────────────────────────────────────────────────────────────
class RedHunter:
    def __init__(self, args: DefaultArgs):
        self.args     = args
        self._local   = threading.local()  # thread-local storage for per-thread sessions
        self.results: List[ScanResult] = []
        self.lock     = threading.Lock()
        self.stats    = {
            "total": 0, "exposed": 0, "critical": 0,
            "scanned": 0, "errors": 0, "new_findings": 0,
            "pages_found": 0, "unreachable": 0,
            "vulns_found": 0, "vuln_critical": 0,
        }
        self.state_db = StateDB(DB_PATH)
        self.notifier: Optional[TelegramNotifier] = None
        if self.args.tg_token and self.args.tg_chat:
            self.notifier = TelegramNotifier(self.args.tg_token, self.args.tg_chat)
        # Background queues — keep scan threads non-blocking
        self._tg_queue    = queue.Queue()
        self._print_queue = queue.Queue()
        self._tg_worker   = threading.Thread(
            target=self._tg_drain, daemon=True, name="tg-notifier"
        )
        self._tg_worker.start()

    def _build_session(self) -> requests.Session:
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        s = requests.Session()
        if self.args.proxy:
            s.proxies = {"http": self.args.proxy, "https": self.args.proxy}
        s.verify = False
        # Connection pooling: large pool for many concurrent threads
        # Retry once on connection reset / transient errors (not on 4xx/5xx)
        retry = Retry(total=0, connect=0, read=0, status=0, raise_on_status=False)
        _pool_size = max(self.args.threads * 2, 40)
        adapter = HTTPAdapter(
            pool_connections=min(_pool_size, 100),
            pool_maxsize=min(_pool_size, 100),
            max_retries=retry,
        )
        s.mount("http://",  adapter)
        s.mount("https://", adapter)
        return s

    def _get_session(self) -> "requests.Session":
        """
        Return this thread's requests.Session, creating it on first access.

        Uses threading.local() so every thread — outer pool, inner pool,
        scheduler, main — gets its own independent session with no sharing.
        This is the ONLY correct way to use threading.local with a thread pool:
        thread pool workers are reused across tasks, so we can't rely on the
        outer scan_target() having initialised the session for inner workers.
        """
        if not getattr(self._local, "session", None):
            self._local.session = self._build_session()
        return self._local.session

    def _headers(self) -> dict:
        h = {
            "User-Agent":      random.choice(USER_AGENTS),
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection":      "keep-alive",
        }
        for raw in (self.args.headers or []):
            if ":" in raw:
                k, v = raw.split(":", 1)
                h[k.strip()] = v.strip()
        return h

    def _normalize(self, target: str) -> str:
        """
        Normalise a target URL to a bare origin: scheme://host[:port]
        Strip any path components the user accidentally included.
        Example: https://example.com/app/v2 → https://example.com
        This ensures every path in SCAN_MODULES is appended to the root.
        """
        t = target.strip().lower()  # normalise scheme/host case before parsing
        # Ensure scheme is present so urllib can parse it
        if not t.startswith(("http://", "https://")):
            t = "https://" + t
        # Strip path, query, fragment — we only want origin
        from urllib.parse import urlparse as _up
        p = _up(t)
        origin = f"{p.scheme}://{p.netloc}"
        # Preserve non-standard ports (already in netloc)
        return origin.rstrip("/")

    def _looks_like_env(self, text: str) -> bool:
        # Strip BOM (Byte Order Mark) — Windows editors add \ufeff to files.
        # Without stripping it, the HTML check and KEY=VALUE scan both fail
        # on the first character of an otherwise valid .env file.
        # Strip BOM (Byte Order Mark) — Windows editors add these to .env files
        for _bom in ('\ufeff', '\ufffe', '\xef\xbb\xbf'):
            if text.startswith(_bom):
                text = text[len(_bom):]
                break
        # Reject HTML pages immediately
        if re.search(r'<html|<body|<!doctype', text[:500], re.IGNORECASE):
            return False
        # Reject pure JSON responses — but ONLY if the entire body is JSON.
        # Do NOT reject .env files that happen to have a JSON-like first line
        # (e.g. corrupted files, merged configs). Check if the whole body
        # parses as JSON, not just if the first char is '{' or '['.
        stripped = text.strip()
        if stripped.startswith(('{', '[')):
            try:
                import json as _json
                _json.loads(stripped)
                # Successfully parsed as pure JSON — not an .env file
                return False
            except Exception:
                # Failed to parse — may be a .env with a JSON-looking first line
                # Don't reject it; let the KEY=VALUE scan below decide.
                pass
        # Require at least 2 KEY=VALUE lines where VALUE is non-empty and non-trivial.
        # KEY must be at least 1 char (changed from {2,} which required 3+, causing
        # keys like 'DB=', 'PW=' to be completely invisible to the scanner).
        real_kv = re.findall(
            r'^[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^\s#\n][^\n]{0,}',
            text, re.MULTILINE  # [A-Za-z_] — catches Node/Python mixed-case keys
                                # e.g. dbHost=, apiKey=, secretKey=
        )
        # Filter out lines that are placeholder values, not real secrets
        actual = [
            ln for ln in real_kv
            if not re.search(
                r'(?i)('
                r'=\s*null\b|=\s*false\b|=\s*true\b|=\s*<|=\s*\{|'
                r'change.?me|changethis|=\s*change\w*|your_|_example|_placeholder|xxx+|=\s*$|'
                # Common placeholder values used in docs / templates
                r'=\s*(password|secret|root|user|admin|test|example|dummy|sample)\s*$|'
                r'example\.com|=\s*replace.?me|some.?random'
                r')',
                ln
            )
        ]
        # Primary check: 2+ real KEY=VALUE lines (standard .env)
        if len(actual) >= 2:
            return True
        # Secondary check: 1 line is enough ONLY if it:
        #   1. Matches a known secret pattern name
        #   2. Uses strict KEY=VALUE format (not shell export/assignment)
        #   3. Is not itself a placeholder
        # Reject common non-.env formats that can produce single KEY=VALUE lines:
        #   - Shell: export FOO=bar, declare FOO=bar, readonly FOO=bar
        #   - INI: [section]\npassword=value (handled by raw_file_modules HTML guard)
        if len(actual) == 1:
            line = actual[0]
            # Reject shell assignment prefixes
            if re.search(r'(?i)^\s*(export|declare|readonly|set|local)\s+', line):
                return False
            high_signal = re.search(
                r'(?i)(DB_PASSWORD|DB_PASS|DATABASE_PASSWORD|'
                r'APP_KEY|SECRET_KEY|API_KEY|JWT_SECRET|ACCESS_TOKEN|'
                r'PRIVATE_KEY|STRIPE_KEY|STRIPE_SECRET|AWS_SECRET|'
                r'SMTP_PASS|MAIL_PASSWORD|SENDGRID_API)',
                line
            )
            if not high_signal:
                return False
            # Guard: reject if the single line itself looks like a placeholder
            return not _FP_RE_COMPILED.search(actual[0])
        return False

    def _is_fp(self, line: str) -> bool:
        return bool(_FP_RE_COMPILED.search(line))

    def _extract_findings(self, content: str) -> dict:
        findings: dict = {}
        for line in content.splitlines():
            line = line.strip()
            if not line or self._is_fp(line):
                continue
            for cat, _cre in _SENS_RE_COMPILED.items():
                if _cre.search(line):
                    display = line
                    if self.args.redact:
                        # Redact: keep key name, hide entire value — never expose any chars
                        display = re.sub(r'(=\s*)(.+)', r'\1****[REDACTED]', line)
                    findings.setdefault(cat, [])
                    if display not in findings[cat]:
                        findings[cat].append(display)
        return findings

    def _risk_level(self, findings: dict) -> str:
        crit = {"Database Credentials", "API Keys", "Cloud Credentials",
                "Auth / JWT Secrets", "Passwords", "Private Keys/Certs"}
        high = {"SMTP / Mail", "OAuth / SSO", "Stripe / Payment", "Twilio / SMS"}
        if any(c in findings for c in crit):
            return "CRITICAL"
        if any(c in findings for c in high):
            return "HIGH"
        if findings:
            return "MEDIUM"
        return "LOW"

    def _fetch_url(self, url: str) -> Optional[ExposedEnv]:
        """Fetch one URL and return an ExposedEnv if it looks like a real .env file.

        REDIRECT STRATEGY — why allow_redirects=False is correct for .env:
          A real exposed .env file returns HTTP 200 directly.
          If a server redirects /.env → /cpanel/ or /login, that means there is
          NO .env file there — the redirect goes to the site's default handler.
          Following that redirect would land on an HTML login page, which
          _looks_like_env() correctly rejects, but wastes time and bandwidth.

          EXCEPTION: we DO follow same-resource redirects — HTTP→HTTPS upgrades
          (301 https://same-host/same-path) and trailing-slash normalisation
          (302 /.env → /.env/). These are safe to follow because the destination
          still points at the .env resource itself.
        """
        def _is_env_redirect(original: str, location: str) -> bool:
            """Return True only if the redirect target is still the .env resource."""
            from urllib.parse import urlparse as _up, urljoin as _uj
            abs_loc = _uj(original, location)
            op = _up(original); lp = _up(abs_loc)
            # Same host (HTTP→HTTPS upgrade counts)
            if op.netloc != lp.netloc:
                return False
            orig_path = op.path.rstrip("/")
            loc_path  = lp.path.rstrip("/")
            # Same path (trailing-slash redirect) or target still looks like env
            return (orig_path == loc_path or
                    loc_path.endswith(".env") or
                    loc_path == "/env")

        def _try_fetch(fetch_url: str, redirects: bool) -> Optional[ExposedEnv]:
            """Inner: fetch fetch_url, return ExposedEnv or None."""
            try:
                resp = self._get_session().get(
                    fetch_url, headers=self._headers(),
                    allow_redirects=redirects,
                    stream=True,
                    timeout=(4, self.args.timeout),
                )
                # If no-redirect and got a redirect: check if worth following
                if not redirects and resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("Location", "")
                    resp.close()
                    if location and _is_env_redirect(fetch_url, location):
                        # Safe redirect (http→https or trailing slash) — follow it
                        return _try_fetch(fetch_url, redirects=True)
                    # Redirect goes somewhere else (login, cpanel…) — not a .env
                    return None

                if resp.status_code not in (200, 206):
                    resp.close()
                    return None

                ct = resp.headers.get("Content-Type", "")
                if not self.args.aggressive:
                    binary = ("image/", "video/", "audio/", "application/pdf",
                              "application/zip", "application/octet-stream",
                              "font/")
                    if any(b in ct for b in binary):
                        resp.close()
                        return None

                # Read at most 64 KB — more than enough for any real .env file
                try:
                    raw_bytes = resp.raw.read(65536, decode_content=True)
                    content   = raw_bytes.decode("utf-8", errors="replace")
                except Exception:
                    resp.close()
                    return None
                finally:
                    resp.close()

                if not self._looks_like_env(content):
                    return None

                # Use the final URL (after any safe redirect) as the finding URL
                final_url = fetch_url
                byte_len  = len(raw_bytes)
                env = ExposedEnv(final_url, resp.status_code, byte_len, ct)
                env.raw_content = content
                env.findings    = self._extract_findings(content)
                env.risk_level  = self._risk_level(env.findings)
                return env

            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout,
                    requests.exceptions.TooManyRedirects):
                return None
            except Exception as e:
                if self.args.verbose:
                    self._print_queue.put(f"[dim red]  [!] {fetch_url}: {e}[/dim red]")
                return None

        # Primary attempt — no redirects (see docstring for why)
        result = _try_fetch(url, redirects=False)
        if result is not None:
            return result

        # HTTP fallback: always try plain HTTP if HTTPS returned nothing.
        # _try_fetch() catches all exceptions internally (SSL, connection, timeout)
        # and returns None — so no outer try/except is needed here.
        # This also handles the case where the server has a broken SSL cert
        # but serves the .env file fine over plain HTTP.
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            return _try_fetch(http_url, redirects=False)

        return None

    def _page_risk(self, module: str) -> str:
        """
        Rate severity by what is DIRECTLY EXPOSED right now — not what an
        attacker could do next.

        CRITICAL  Credentials or private data readable with zero authentication.
                  config_files : signature requires actual DB_PASSWORD=/API_KEY=
                                 with a real value present in the file
                  backup_files : SQL dump confirmed (INSERT INTO / CREATE TABLE)
                  ssh_keys     : private key header confirmed in response body

        HIGH      Sensitive structure exposed; likely contains secrets on inspection.
                  git_exposure : source code + full commit history accessible
                  devops_files : docker-compose/Dockerfile (frequently has passwords)

        MEDIUM    Interface is reachable but requires a further step to exploit.
                  phpmyadmin   : login page up — attacker still needs credentials
                  admin_panels : cPanel/WHM/Plesk login — not unauthenticated access
                  php_info     : server internals visible, no credentials directly
                  log_files    : stack traces may leak tokens, not guaranteed
                  wordpress    : user list / XML-RPC exposed, not passwords

        LOW       Pure info disclosure — versions, API schema, dependency lists.
                  server_status : connection counts, server version
                  api_exposure  : Swagger/OpenAPI schema only
                  package_files : dependency list only
        """
        critical = {"config_files", "backup_files", "ssh_keys",
                    "cloud_metadata", "exposed_secrets", "database_exposure"}
        high     = {"git_exposure", "devops_files",
                    "cicd_exposure", "kubernetes"}
        medium   = {"phpmyadmin", "admin_panels", "php_info",
                    "log_files", "wordpress"}
        # server_status, api_exposure, package_files → LOW (info disclosure only)
        if module in critical: return "CRITICAL"
        if module in high:     return "HIGH"
        if module in medium:   return "MEDIUM"
        return "LOW"

    def _fetch_page(self, url: str, module: str) -> Optional[ExposedPage]:
        """
        Fetch a non-.env URL and check if it's genuinely exposed.

        KEY DESIGN DECISIONS:
        - Redirects are DISABLED by default. A genuine exposed resource
          responds 200 directly. If /admin/ redirects to /login.php that
          means the admin panel is PROTECTED — it requires authentication.
          Following the redirect would land on a login form which contains
          "password" and "username" words, causing false positives.
        - Signatures use OR logic: ANY one matching pattern = confirmed exposure.
          Each signature is specific enough that a single match is conclusive.
        - Evidence shown in the report is the matched line from the
          response, not just the tiny regex token.
        """
        # Modules where following redirects is valid
        # (e.g. server status pages sometimes redirect to their canonical path)
        redirect_ok = {"server_status", "api_exposure", "php_info"}

        try:
            # HEAD first: get status with zero body transfer.
            # ~95% of probe paths return 404/403 — HEAD rejects them in <50ms
            # with no body downloaded. Only 200s get a full GET + body read.
            _allow_redir = (module in redirect_ok)
            try:
                _head = self._get_session().head(
                    url, headers=self._headers(),
                    allow_redirects=_allow_redir,
                    timeout=(4, 4),  # 4s connect+read: cPanel/shared hosts are slow
                )
                _head.close()
                if _head.status_code not in (200, 206):
                    return None
            except Exception:
                return None

            # Status 200 confirmed — fetch body to run signature checks
            resp = self._get_session().get(
                url,
                headers=self._headers(),
                allow_redirects=_allow_redir,
                stream=True,
                timeout=(4, self.args.timeout),  # 4s connect for slow hosts
            )

            if resp.status_code not in (200, 206):
                resp.close()
                return None

            # Capture status_code before entering body-read try/finally.
            # This ensures it is always bound when ExposedPage is constructed.
            _status_code = resp.status_code

            # Read at most 16KB — signature matching only uses first 8KB anyway.
            # Capping here prevents downloading full pages for every probe.
            try:
                raw_bytes = resp.raw.read(16384, decode_content=True)
                content   = raw_bytes.decode("utf-8", errors="replace")
            except Exception:
                resp.close()
                return None
            finally:
                resp.close()

            if not content or len(content) < 50:
                return None

            # ── Module-specific content-type guard ────────────────────────────
            # Raw file modules (git, ssh, backup, package, devops, config)
            # should NEVER return HTML — if they do it's a soft 404 or CMS page.
            raw_file_modules = {
                "git_exposure", "ssh_keys", "backup_files",
                "package_files", "devops_files", "config_files", "log_files",
                "exposed_secrets", "cloud_metadata", "kubernetes",
                "database_exposure", "cicd_exposure",
            }
            if module in raw_file_modules:
                if re.search(r'<html|<!doctype|<head\b|<body\b', content[:500], re.IGNORECASE):
                    return None

            # ── Soft 404 detection ─────────────────────────────────────────────
            # Many sites return HTTP 200 for every non-existent URL
            # with a custom "Page Not Found" page. Reject these BEFORE
            # running signature checks to avoid false positives.
            # _SOFT_404_RE is pre-compiled at module level (single combined pattern)
            if _SOFT_404_RE.search(content[:3000]):
                return None  # Soft 404 — discard

            # ── Signature validation ───────────────────────────────────────────
            # OR logic: ANY one signature match = confirmed genuine exposure.
            # Each signature is specific enough that a single match is conclusive.
            sigs = MODULE_SIGNATURES.get(module, [])
            evidence: List[str] = []

            if sigs:
                search_zone = content[:8000]  # check first 8KB for speed
                # ── OR logic: ANY one signature match = confirmed exposure ──────
                # Each signature is specific enough that a single match is conclusive.
                # Different files in the same module (e.g. .git/HEAD vs .git/config
                # vs packed-refs) each match different patterns — AND logic would
                # require ALL to match simultaneously which is impossible for
                # single-file responses. OR logic is correct here.
                first_match = None
                for sig in sigs:
                    m = re.search(sig, search_zone, re.MULTILINE)
                    if m:
                        first_match = m
                        break
                if not first_match:
                    return None  # No signature matched — not a genuine exposure
                # Extract evidence: full line containing the match (shows real context)
                # This replaces the old "bare matched word" approach that showed
                # evidence like "• head" instead of "• ref: refs/heads/main"
                for sig in sigs:
                    m = re.search(sig, search_zone, re.MULTILINE)
                    if not m:
                        continue
                    m_pos      = m.start()
                    line_start = search_zone.rfind('\n', 0, m_pos) + 1
                    line_end   = search_zone.find('\n', m.end())
                    if line_end == -1:
                        line_end = min(m_pos + 200, len(search_zone))
                    raw_line   = search_zone[line_start:line_end].strip()
                    # Strip HTML tags for clean display in Telegram/reports
                    clean_line = re.sub(r'<[^>]+>', ' ', raw_line)
                    clean_line = re.sub(r'\s+', ' ', clean_line).strip()
                    if not clean_line:
                        clean_line = m.group(0)[:80].strip()
                    if clean_line and clean_line not in evidence:
                        evidence.append(clean_line[:120])
                    if len(evidence) >= 4:
                        break
            else:
                # No signatures defined for this module — trust HTTP 200 only
                # if the content is substantial (not a redirect/error page)
                if len(content) < 200:
                    return None
                # Additional guard: reject if it looks like an HTML page
                # when we expected a raw file (backup, key, etc.)
                if re.search(r'<html|<!doctype', content[:200], re.IGNORECASE):
                    return None

            label            = SCAN_MODULES.get(module, {}).get("label", module)
            page             = ExposedPage(url, _status_code, len(raw_bytes),
                                           module, label, evidence)
            page.risk_level  = self._page_risk(module)
            page.raw_snippet = content[:500]
            return page

        except requests.exceptions.SSLError:
            return None  # SSL failure — skip rather than recurse or retry
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects):
            pass
        except Exception as e:
            if self.args.verbose:
                self._print_queue.put(f"[dim red]  [!] {url}: {e}[/dim red]")
        return None

    def _tg_drain(self):
        """Background thread: sends Telegram notifications without blocking scan threads.
        Errors go to stderr — NOT the Rich console — because Rich is not thread-safe
        when called from a background thread during Progress rendering."""
        while True:
            item = self._tg_queue.get()
            if item is None:
                self._tg_queue.task_done()
                break
            fn, args, kwargs = item
            try:
                fn(*args, **kwargs)
            except Exception as _tg_exc:
                # Bare except is intentional: this thread MUST NOT crash.
                # Log to stderr (safe from any thread) — not Rich which is not thread-safe.
                import sys as _sys
                print(f"[RedHunter] TG worker error: {_tg_exc}", file=_sys.stderr)
            finally:
                self._tg_queue.task_done()

    def _tg_notify(self, fn, *args, **kwargs):
        """Non-blocking: enqueue a Telegram call for the background worker."""
        self._tg_queue.put((fn, args, kwargs))

    def scan_target(self, target: str) -> ScanResult:
        # Session is created lazily by _get_session() — works for both outer
        # and inner thread pool workers without explicit init here.
        target = self._normalize(target)
        result = ScanResult(target)
        result.scan_status = "running"

        # ── Host reachability pre-check ──────────────────────────────────────
        # Goals:
        #   1. Skip truly dead hosts fast (saves 322 × 2s timeout = 644s)
        #   2. NOT skip live hosts that return 403/429/503 on "/" (anti-bot)
        #   3. NOT skip hosts that are slow to respond but alive
        # Strategy:
        #   - HEAD "/" with 4s connect timeout (generous for CDN/slow sites)
        #   - ANY HTTP response code = host is alive, continue scanning
        #   - Only ConnectionError / connect-timeout = truly dead, skip
        #   - SSL failure on HTTPS → retry once over HTTP before giving up
        _alive = False
        _connect_exc = None
        for _scheme_try in (target, target.replace("https://", "http://", 1)):
            try:
                self._get_session().head(
                    _scheme_try + "/", headers=self._headers(),
                    allow_redirects=True, timeout=(5, 8),
                )
                _alive = True
                break  # Any HTTP response = alive
            except requests.exceptions.SSLError:
                _connect_exc = "ssl"
                continue  # Try HTTP fallback
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout):
                _connect_exc = "conn"
                continue  # Try HTTP fallback before giving up
            except Exception:
                _alive = True  # Unexpected error ≠ dead host — scan anyway
                break
        if not _alive:
            result.scan_status = "unreachable"
            if not self.args.quiet:
                self._print_queue.put(f"[dim]  [~] Unreachable (skipped): {target}[/dim]")
            return result

        # ── Build full work list ─────────────────────────────────────────────
        # vuln_only: skip ALL exposure probes — only vuln fingerprinting runs below
        work: list = []
        if not getattr(self.args, "vuln_only", False):
            env_paths = list(SCAN_MODULES["env_files"]["paths"])
            for p in (self.args.extra_paths or []):
                if p not in env_paths:
                    env_paths.append(p)
            for path in env_paths:
                work.append((target + path, "env", "env_files"))
            for mod_key, mod_cfg in SCAN_MODULES.items():
                if mod_key == "env_files" or not mod_cfg.get("enabled", True):
                    continue
                for path in mod_cfg["paths"]:
                    work.append((target + path, "page", mod_key))

        # ── Inner probe worker ───────────────────────────────────────────────
        def _probe(item):
            """
            Probe a single URL. Called from inner thread pool workers.
            _get_session() ensures each worker thread has its own HTTP session —
            this is the fix for '_thread._local object has no attribute session'.
            """
            try:
                url, kind, module = item
                if kind == "env":
                    env = self._fetch_url(url)
                    if not env:
                        return None
                    is_new = self.state_db.mark_seen_atomic(env)
                    if self.args.verbose:
                        rc = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"cyan","LOW":"green"}.get(env.risk_level,"white")
                        badge = "[bold green][NEW][/bold green]   " if is_new else "[dim][KNOWN][/dim] "
                        self._print_queue.put(f"  {badge}[bold {rc}]✓ .env [{env.risk_level}] {url}[/bold {rc}]")
                    if is_new:
                        # Count ALL new .env findings regardless of risk or notifier state
                        with self.lock:
                            self.stats["new_findings"] += 1
                        # Alert only for MEDIUM+ risk (LOW .env = no real secrets found)
                        if self.notifier and env.risk_level != "LOW":
                            self._tg_notify(self.notifier.send_finding, env, target, is_new=True)
                    return ("env", env)
                else:
                    page = self._fetch_page(url, module)
                    if not page:
                        return None
                    is_new = self.state_db.mark_seen_page_atomic(page)
                    if self.args.verbose:
                        rc = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"cyan","LOW":"green"}.get(page.risk_level,"white")
                        badge = "[bold green][NEW][/bold green]   " if is_new else "[dim][KNOWN][/dim] "
                        self._print_queue.put(f"  {badge}[bold {rc}]✓ {page.label} [{page.risk_level}] {url}[/bold {rc}]")
                    # Count ALL new page findings, regardless of risk level.
                    # TG alert fires for every new finding — risk context explains severity.
                    if is_new:
                        with self.lock:
                            self.stats["new_findings"] += 1
                        if self.notifier:
                            self._tg_notify(self.notifier.send_page_finding, page, target)
                    return ("page", page)
            except Exception as _probe_err:
                if self.args.verbose:
                    self._print_queue.put(f"[dim red]  [!] probe error {item[0] if item else '?'}: {_probe_err}[/dim red]")
                return None

        # ── Dispatch all paths in parallel (inner pool per target) ──────────
        # All env AND page paths run in the SAME thread pool simultaneously.
        # as_completed() processes whichever finishes first — no phasing.
        #
        # PATH_WORKERS scaling strategy:
        #   Single target (outer threads=1):  push up to 50 workers — maximise speed
        #   Multi-target (outer threads>1):   use configured path_workers (default 20)
        #   vuln_only: work list is empty, skip entirely
        if work:
            _outer_threads = getattr(self.args, "threads", 25)
            _pw_cfg = getattr(self.args, "path_workers", 20)
            if _outer_threads == 1:
                # Single target mode — push inner workers high
                PATH_WORKERS = min(max(_pw_cfg, 30), 80)
            else:
                PATH_WORKERS = min(max(_pw_cfg, 20), 50)
            with ThreadPoolExecutor(max_workers=PATH_WORKERS) as inner:
                for fut in as_completed([inner.submit(_probe, item) for item in work]):
                    try:
                        res = fut.result()
                        if res:
                            kind, obj = res
                            if kind == "env":
                                result.exposed_envs.append(obj)
                            else:
                                result.exposed_pages.append(obj)
                    except Exception as _probe_err:
                        if self.args.verbose:
                            self._print_queue.put(
                                f"[dim red]  [!] probe error: {_probe_err}[/dim red]"
                            )

        # ── Vulnerability fingerprinting ──────────────────────────────────────
        if getattr(self.args, "vuln_scan", False) or getattr(self.args, "vuln_only", False):
            try:
                vs = VulnScanner(self.args, self._get_session)
                vr = vs.run(target)
                for vf in vr.get("vuln_findings", []):
                    result.vuln_results.append(vf)
                    is_new_vuln = self.state_db.mark_seen_vuln_atomic(vf)
                    with self.lock:
                        self.stats["vulns_found"] += 1
                        if vf.severity == "CRITICAL":
                            self.stats["vuln_critical"] += 1
                    if self.args.verbose:
                        sc = {"CRITICAL":"red","HIGH":"yellow","MEDIUM":"cyan","LOW":"green"}.get(vf.severity,"white")
                        badge = "[bold green][NEW][/bold green]   " if is_new_vuln else "[dim][KNOWN][/dim] "
                        self._print_queue.put(
                            f"  {badge}[bold {sc}][VULN] {vf.severity} {vf.cve} — "
                            f"{vf.plugin} v{vf.installed_version}[/bold {sc}]"
                        )
                    # Only alert Telegram for NEW vuln findings — avoids alert fatigue
                    if self.notifier and is_new_vuln:
                        self._tg_notify(self.notifier.send_vuln_finding, vf)
                result.ajax_surfaces = vr.get("ajax_surfaces", {})
                result.xmlrpc        = vr.get("xmlrpc")
                for page in result.exposed_pages:
                    if page.module == "phpmyadmin" and page.raw_snippet:
                        pma_score = vs.score_phpmyadmin(target, page.raw_snippet)
                        if pma_score:
                            result.pma_scores.append({"url": page.url, **pma_score})
                            if self.args.verbose:
                                self._print_queue.put(
                                    f"  [bold red][PMA] Session score {pma_score['score']} @ {page.url}[/bold red]"
                                )
            except Exception as _vs_err:
                if self.args.verbose:
                    self._print_queue.put(f"[dim red]  [!] VulnScanner error @ {target}: {_vs_err}[/dim red]")

        result.scan_status = "done"
        return result

    def run(self, targets: List[str]) -> List[ScanResult]:
        self.stats["total"] = len(targets)

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold red]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[bold white]{task.completed}/{task.total}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[bold red]Scanning targets...", total=len(targets))
            with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                futures = {executor.submit(self.scan_target, t): t for t in targets}
                for future in as_completed(futures):
                    try:
                        # Hard per-target timeout: prevents a single black-hole
                        # host from hanging the entire scan indefinitely.
                        # 14 modules × timeout × 2 = generous ceiling per target.
                        _tgt_timeout = max(120, 14 * self.args.timeout * 2)
                        result = future.result(timeout=_tgt_timeout)
                        with self.lock:
                            self.results.append(result)
                            if result.scan_status == "unreachable":
                                self.stats["unreachable"] += 1
                            else:
                                self.stats["scanned"] += 1
                            if result.exposed_envs:
                                self.stats["exposed"] += len(result.exposed_envs)
                                for env in result.exposed_envs:
                                    if env.risk_level == "CRITICAL":
                                        self.stats["critical"] += 1
                            # pages_found inside lock — thread safe
                            if result.exposed_pages:
                                self.stats["pages_found"] += len(result.exposed_pages)
                                for page in result.exposed_pages:
                                    if page.risk_level == "CRITICAL":
                                        self.stats["critical"] += 1
                            # vuln stats updated inside scan_target via lock
                    except Exception as e:
                        with self.lock:
                            self.stats["errors"] += 1
                        _tgt = futures.get(future, "unknown")
                        if type(e).__name__ in ("TimeoutError", "CancelledError"):
                            console.print(
                                f"[yellow]  [!] Target abandoned (no response): {_tgt}[/yellow]"
                            )
                        elif self.args.verbose:
                            console.print(f"[red]  [!] Scan error: {e}[/red]")
                    finally:
                        progress.advance(task)
                        # Flush verbose output from completed target (main thread only)
                        while True:
                            try:
                                console.print(self._print_queue.get_nowait())
                            except queue.Empty:
                                break
                        # Inter-TARGET delay: the full stealth delay now applies
                        # BETWEEN targets, not between each of 280 paths within one.
                        if self.args.delay:
                            time.sleep(random.uniform(
                                self.args.delay * 0.5, self.args.delay
                            ))

        if self.notifier:
            # Enqueue final summary — _tg_queue.join() in close() waits for it
            self._tg_notify(self.notifier.send_summary, self.stats)

        return self.results

    def close(self):
        # Drain Telegram queue then stop worker cleanly
        try:
            self._tg_queue.put(None)  # sentinel: signals worker to stop
            self._tg_queue.join()     # blocks until all items incl. sentinel done
            self._tg_worker.join(timeout=5)
        except Exception:
            pass
        self.state_db.close()
        # Close this thread's local session if it exists
        try:
            s = getattr(self._local, "session", None)
            if s:
                s.close()
                self._local.session = None
        except Exception:
            pass


# ─── REPORTER ─────────────────────────────────────────────────────────────────
RISK_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "yellow",
    "MEDIUM":   "cyan",
    "LOW":      "green",
}

class Reporter:
    def __init__(self, results: List[ScanResult], stats: dict, args: DefaultArgs):
        self.results = results
        self.stats   = stats
        self.args    = args

    def _rc(self, level: str) -> str:
        return RISK_COLORS.get(level, "white")

    def print_summary_table(self):
        console.print()
        t = Table(
            title="[bold cyan]Scan Summary[/bold cyan]",
            box=box.DOUBLE_EDGE, border_style="cyan", show_lines=True
        )
        t.add_column("Target",        style="bold white", no_wrap=True)
        t.add_column("Source",        justify="center")
        t.add_column(".env Status",   justify="center")
        t.add_column(".env Paths",    justify="center")
        t.add_column("Pages Found",   justify="center")
        t.add_column("Vulns",         justify="center")
        t.add_column("Findings",      justify="center")
        t.add_column("Risk",          justify="center")
        for r in self.results:
            src_label = f"[dim]{r.source}[/dim]"
            # Determine highest risk across both env and page findings
            all_risks  = ([e.risk_level for e in r.exposed_envs] +
                          [p.risk_level for p in r.exposed_pages])
            risk_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            highest    = max(all_risks, key=lambda x: risk_order.index(x)) if all_risks else None
            tf         = sum(len(v) for e in r.exposed_envs for v in e.findings.values())
            pages_n    = len(r.exposed_pages)

            if r.exposed_envs or r.exposed_pages:
                env_status = "[bold green]✓ .env EXPOSED[/bold green]" if r.exposed_envs else "[dim]✗ .env Clean[/dim]"
                vuln_n = len(getattr(r, "vuln_results", []))
                vuln_col = f"[bold red]{vuln_n}[/bold red]" if vuln_n else "[dim]0[/dim]"
                t.add_row(
                    r.target, src_label, env_status,
                    str(len(r.exposed_envs)),
                    str(pages_n) if pages_n else "[dim]0[/dim]",
                    vuln_col,
                    str(tf),
                    f"[{self._rc(highest)}]{highest}[/{self._rc(highest)}]"
                )
            elif r.scan_status == "unreachable":
                t.add_row(r.target, src_label,
                          "[dim yellow]~ Unreachable[/dim yellow]",
                          "[dim]—[/dim]", "[dim]—[/dim]",
                          "[dim]—[/dim]", "[dim]—[/dim]", "[dim]—[/dim]")
            else:
                t.add_row(r.target, src_label, "[dim]✗ Clean[/dim]",
                          "0", "0", "0", "0", "[dim]—[/dim]")
        console.print(t)

    def print_findings(self):
        for r in self.results:
            if not r.exposed_envs:
                continue
            console.print()
            console.print(Panel(
                f"[bold white]Target:[/bold white] {r.target}  [dim]({r.source})[/dim]\n"
                f"[bold white]Time:[/bold white]   {r.timestamp}",
                title="[bold cyan]◉ Exposed Target[/bold cyan]", border_style="cyan"
            ))
            for env in r.exposed_envs:
                rc = self._rc(env.risk_level)
                console.print(
                    f"\n  [bold white]URL:[/bold white] {env.url}\n"
                    f"  [bold white]HTTP:[/bold white] {env.status_code}  "
                    f"[bold white]Size:[/bold white] {env.content_length}B  "
                    f"[bold white]Risk:[/bold white] [{rc}]{env.risk_level}[/{rc}]"
                )
                if env.findings:
                    ft = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
                    ft.add_column("Category",      style="bold yellow")
                    ft.add_column("Matched Lines", style="white")
                    for cat, lines in env.findings.items():
                        for i, ln in enumerate(lines):
                            ft.add_row(cat if i == 0 else "", ln[:120])
                    console.print(ft)
                else:
                    console.print("  [dim]  .env found but no sensitive keywords matched.[/dim]")
                if self.args.show_content:
                    console.print(Panel(
                        env.raw_content[:3000],
                        title="[dim]Raw .env Content (first 3000 chars)[/dim]",
                        border_style="dim"
                    ))

    def print_stats(self):
        console.print()
        console.print(Panel(
            f"[bold white]Total Targets  :[/bold white]  {self.stats.get('total', 0)}\n"
            f"[bold white]Scanned        :[/bold white]  {self.stats.get('scanned', 0)}\n"
            f"[bold green].env Exposed   :[/bold green]  {self.stats.get('exposed', 0)}\n"
            f"[bold green]Pages Exposed  :[/bold green]  {self.stats.get('pages_found', 0)}\n"
            f"[bold red]Critical       :[/bold red]  {self.stats.get('critical', 0)}\n"
            f"[bold cyan]New Findings   :[/bold cyan]  {self.stats.get('new_findings', 0)}\n"
            f"[bold yellow]Errors         :[/bold yellow]  {self.stats.get('errors', 0)}\n"
            f"[dim]Unreachable    :[/dim]  {self.stats.get('unreachable', 0)}\n"
            f"[bold red]Vulns Found    :[/bold red]  {self.stats.get('vulns_found', 0)}\n"
            f"[bold red]Vuln Critical  :[/bold red]  {self.stats.get('vuln_critical', 0)}",
            title="[bold red]◉ Final Statistics[/bold red]", border_style="red"
        ))

    def print_page_findings(self):
        """Print all non-.env web exposure findings."""
        page_results = [r for r in self.results if r.exposed_pages]
        if not page_results:
            return
        console.print()
        console.print(Panel(
            "[bold white]Non-.env resources publicly accessible[/bold white]",
            title="[bold cyan]◉ Web Exposure Findings[/bold cyan]", border_style="cyan"
        ))
        for r in page_results:
            for page in r.exposed_pages:
                rc = self._rc(page.risk_level)
                _ctx_map = {
                    "CRITICAL": "Credentials/data directly readable — no auth required",
                    "HIGH":     "Sensitive structure exposed — likely contains secrets",
                    "MEDIUM":   "Login interface reachable — attacker needs credentials",
                    "LOW":      "Info disclosure only — versions/schema, no credentials",
                }
                _ctx = _ctx_map.get(page.risk_level, "")
                console.print(
                    f"\n  [{rc}]■[/{rc}] [bold white]{page.label}[/bold white]  "
                    f"[{rc}][{page.risk_level}][/{rc}]"
                )
                if _ctx:
                    console.print(f"    [dim]→ {_ctx}[/dim]")
                console.print(f"    [bold white]URL   :[/bold white] {page.url}")
                console.print(f"    [bold white]HTTP  :[/bold white] {page.status_code}  "
                              f"[bold white]Size:[/bold white] {page.content_length}B")
                if page.evidence:
                    console.print("    [bold white]Evidence:[/bold white]")
                    for ev in page.evidence[:5]:
                        console.print(f"      [dim yellow]→[/dim yellow] {ev}")
                if self.args.show_content and page.raw_snippet:
                    console.print(Panel(
                        page.raw_snippet[:500],
                        title="[dim]Response Snippet[/dim]", border_style="dim"
                    ))


    def print_vuln_findings(self):
        """Print all confirmed vulnerability surfaces in a rich table."""
        all_vulns = [vf for r in self.results for vf in getattr(r, "vuln_results", [])]
        ajax_map  = {r.target: getattr(r, "ajax_surfaces", {}) for r in self.results}
        xmlrpc_map= {r.target: getattr(r, "xmlrpc", None) for r in self.results}
        pma_map   = {r.target: getattr(r, "pma_scores", []) for r in self.results}

        if not all_vulns and not any(ajax_map.values()) and not any(xmlrpc_map.values()):
            return

        console.print()
        console.print(Panel(
            "[bold red]◉ Vulnerability Scan Results[/bold red]",
            border_style="red"
        ))

        # ── CVE Findings table ────────────────────────────────────────────────
        if all_vulns:
            t = Table(
                title="[bold red]Plugin CVE Findings[/bold red]",
                box=box.DOUBLE_EDGE, border_style="red", show_lines=True
            )
            t.add_column("Target",    style="bold white", no_wrap=True, max_width=35)
            t.add_column("Plugin",    style="cyan",       max_width=30)
            t.add_column("Version",   justify="center")
            t.add_column("CVE",       justify="center",   style="bold")
            t.add_column("CVSS",      justify="center")
            t.add_column("Severity",  justify="center")
            t.add_column("Title",     max_width=35)
            t.add_column("Surface ✓", justify="center")
            for vf in all_vulns:
                rc    = self._rc(vf.severity)
                cvss  = f"[{rc}]{vf.cvss}[/{rc}]"
                sev   = f"[{rc}]{vf.severity}[/{rc}]"
                surf  = "[bold green]YES[/bold green]" if vf.surface_url else "[dim]—[/dim]"
                t.add_row(
                    vf.target, vf.plugin,
                    f"v{vf.installed_version}  →  [green]≥{vf.fixed_in}[/green]",
                    f"[bold]{vf.cve}[/bold]",
                    cvss, sev, vf.title, surf
                )
            console.print(t)

            # Per-finding detail panels
            for vf in all_vulns:
                rc = self._rc(vf.severity)
                refs = "\n".join(f"  {r}" for r in vf.references) or "  (no public references)"
                surf_line = f"\n  [bold]Surface URL :[/bold] {vf.surface_url}" if vf.surface_url else ""
                console.print(Panel(
                    f"[bold {rc}]{vf.severity}[/bold {rc}] — "
                    f"[bold]{vf.cve}[/bold]  CVSS {vf.cvss}\n"
                    f"[bold]Plugin  :[/bold] {vf.plugin} v{vf.installed_version}\n"
                    f"[bold]Fixed   :[/bold] v{vf.fixed_in}\n"
                    f"[bold]Surface :[/bold] {vf.surface}{surf_line}\n"
                    f"\n[bold]Description:[/bold]\n{vf.description}\n"
                    f"\n[bold]Recommended:[/bold]\n[green]{vf.recommend}[/green]\n"
                    f"\n[bold]References:[/bold]\n{refs}",
                    title=f"[bold red]◉ {vf.title}[/bold red]",
                    border_style=rc
                ))

        # ── AJAX Surface table ────────────────────────────────────────────────
        ajax_rows = [(t, p, s) for t, m in ajax_map.items() for p, s in m.items()]
        if ajax_rows:
            console.print()
            ta = Table(
                title="[bold yellow]AJAX / Upload Surfaces Reachable[/bold yellow]",
                box=box.SIMPLE_HEAVY, border_style="yellow", show_lines=True
            )
            ta.add_column("Target",   style="bold white", max_width=40)
            ta.add_column("Path",     style="cyan")
            ta.add_column("HTTP",     justify="center")
            ta.add_column("Risk Note")
            for tgt, path, status in ajax_rows:
                risk_note = ""
                if "admin-ajax.php" in path:
                    risk_note = "WordPress AJAX endpoint — unauthenticated actions may be registered"
                elif "wp-json" in path:
                    risk_note = "WordPress REST API active — user enumeration & unauthenticated endpoints possible"
                elif "xmlrpc" in path:
                    risk_note = "XML-RPC active — brute-force / multicall surface"
                elif "FileUploader" in path:
                    risk_note = "[bold red]Legacy file uploader — direct PHP upload surface[/bold red]"
                ta.add_row(tgt, path, str(status), risk_note)
            console.print(ta)

        # ── XML-RPC findings ──────────────────────────────────────────────────
        for tgt, xr in xmlrpc_map.items():
            if xr:
                console.print(Panel(
                    f"[bold yellow]⚠ XML-RPC Active[/bold yellow]\n"
                    f"[bold]Target :[/bold] {tgt}\n"
                    f"[bold]URL    :[/bold] {xr['url']}\n"
                    f"[bold]Note   :[/bold] {xr['note']}\n"
                    f"[bold]Risk   :[/bold] {xr['risk']}",
                    title="[bold yellow]◉ XML-RPC Surface[/bold yellow]",
                    border_style="yellow"
                ))

        # ── phpMyAdmin session scores ─────────────────────────────────────────
        for tgt, scores in pma_map.items():
            for sc in scores:
                rc = self._rc(sc.get("risk", "MEDIUM"))
                console.print(Panel(
                    f"[bold {rc}]phpMyAdmin Session Quality Score: {sc['score']}[/bold {rc}]\n"
                    f"[bold]URL      :[/bold] {sc['url']}\n"
                    f"[bold]Auth signs:[/bold] {'Yes' if sc.get('auth_signs') else 'No'}\n"
                    f"[bold]Large body:[/bold] {'Yes (>20KB)' if sc.get('large_body') else 'No'}\n"
                    f"[bold]Indicators:[/bold] {len(sc.get('indicators',[]))} matched\n"
                    f"\n[dim]Score interpretation: ≥8=CRITICAL (likely auth'd session visible) "
                    f"| 4-7=HIGH | <4=MEDIUM[/dim]",
                    title=f"[bold {rc}]◉ phpMyAdmin Analysis[/bold {rc}]",
                    border_style=rc
                ))

    def save_json(self, path: str):
        data = []
        for r in self.results:
            # Include target if it has ANY finding — env, page, OR vuln
            if not r.exposed_envs and not r.exposed_pages and not getattr(r, "vuln_results", []):
                continue
            entry = {
                "target": r.target, "source": r.source,
                "timestamp": r.timestamp,
                "exposed_env_files": [],
                "exposed_pages": [],
                "vuln_findings": [],
                "ajax_surfaces": getattr(r, "ajax_surfaces", {}),
                "xmlrpc": getattr(r, "xmlrpc", None),
            }
            for env in r.exposed_envs:
                entry["exposed_env_files"].append({
                    "url":            env.url,
                    "status_code":    env.status_code,
                    "content_length": env.content_length,
                    "content_type":   env.content_type,
                    "risk_level":     env.risk_level,
                    "findings":       env.findings,
                    "raw_content":    env.raw_content if not self.args.redact else "[REDACTED]",
                })
            for page in r.exposed_pages:
                entry["exposed_pages"].append({
                    "url":            page.url,
                    "status_code":    page.status_code,
                    "content_length": page.content_length,
                    "module":         page.module,
                    "label":          page.label,
                    "risk_level":     page.risk_level,
                    "evidence":       page.evidence,
                    "raw_snippet":    page.raw_snippet if not self.args.redact else "[REDACTED]",
                })
            for vf in getattr(r, "vuln_results", []):
                entry["vuln_findings"].append({
                    "plugin":            vf.plugin,
                    "installed_version": vf.installed_version,
                    "cve":               vf.cve,
                    "cvss":              vf.cvss,
                    "severity":          vf.severity,
                    "title":             vf.title,
                    "description":       vf.description,
                    "fixed_in":          vf.fixed_in,
                    "surface":           vf.surface,
                    "surface_url":       vf.surface_url,
                    "recommend":         vf.recommend,
                    "references":        vf.references,
                    "timestamp":         vf.timestamp,
                })
            data.append(entry)
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            console.print(f"[bold green]✔[/bold green] JSON → [cyan]{path}[/cyan]")
        except OSError as e:
            console.print(f"[red]  [!] Could not write JSON: {e}[/red]")

    def save_txt(self, path: str):
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"RedHunter v{VERSION} | {AUTHOR} | {TG_HANDLE}\n")
                f.write(f"Date: {datetime.now(timezone.utc).isoformat()} UTC\n")
                f.write("=" * 70 + "\n\n")
                exposed_count = 0
                for r in self.results:
                    # Include targets with ANY finding: env, page, OR vuln
                    if not r.exposed_envs and not r.exposed_pages and not getattr(r, "vuln_results", []):
                        continue
                    exposed_count += 1
                    f.write(f"TARGET: {r.target}  [source: {r.source}]\n")
                    # .env file findings
                    for env in r.exposed_envs:
                        f.write(f"  [.ENV FILE]\n")
                        f.write(f"  URL:        {env.url}\n")
                        f.write(f"  HTTP:       {env.status_code}\n")
                        f.write(f"  Size:       {env.content_length}B\n")
                        f.write(f"  Risk Level: {env.risk_level}\n")
                        for cat, lines in env.findings.items():
                            f.write(f"  [{cat}]\n")
                            for ln in lines:
                                f.write(f"    {ln}\n")
                        f.write("\n")
                    # Web exposure page findings — BUG 7: indentation was broken
                    for page in r.exposed_pages:
                        f.write(f"  [WEB EXPOSURE] {page.label}\n")
                        f.write(f"  URL:        {page.url}\n")
                        f.write(f"  HTTP:       {page.status_code}\n")
                        f.write(f"  Size:       {page.content_length}B\n")
                        f.write(f"  Risk Level: {page.risk_level}\n")
                        for ev in page.evidence:
                            f.write(f"    → {ev}\n")
                        f.write("\n")
                    # Vulnerability findings
                    for vf in getattr(r, "vuln_results", []):
                        f.write(f"  [VULNERABILITY] {vf.severity} — {vf.cve}\n")
                        f.write(f"  Plugin:   {vf.plugin} v{vf.installed_version}\n")
                        f.write(f"  Fixed In: v{vf.fixed_in}\n")
                        f.write(f"  CVSS:     {vf.cvss}\n")
                        f.write(f"  Title:    {vf.title}\n")
                        f.write(f"  Surface:  {vf.surface_url or 'not confirmed'}\n")
                        f.write(f"  Action:   {vf.recommend}\n")
                        f.write("\n")
                if exposed_count == 0:
                    f.write("No exposures found.\n")
            console.print(f"[bold green]✔[/bold green] TXT  → [cyan]{path}[/cyan]")
        except OSError as e:
            console.print(f"[red]  [!] Could not write TXT: {e}[/red]")

    def save_html(self, path: str):
        rows = ""
        for r in self.results:
            # BUG FIX: don't skip targets that only have page findings
            for env in r.exposed_envs:
                rc = {"CRITICAL": "critical", "HIGH": "high",
                      "MEDIUM": "medium", "LOW": "low"}.get(env.risk_level, "low")
                fh = ""
                for c, ls in env.findings.items():
                    fh += f"<b>{c}:</b><br>"
                    for ln in ls:
                        # HTML-escape angle brackets
                        safe_ln = ln.replace("<", "&lt;").replace(">", "&gt;")
                        fh += f"&nbsp;&nbsp;<code>{safe_ln[:120]}</code><br>"
                if not fh:
                    fh = "<em>No sensitive keywords matched</em>"
                safe_url    = html.escape(env.url, quote=True)
                safe_target = r.target.replace("<", "&lt;").replace(">", "&gt;")
                rows += (
                    f"<tr>"
                    f"<td>{safe_target}<br><small class='src'>[{r.source}]</small></td>"
                    f"<td><a href=\"{safe_url}\" target=\"_blank\">{html.escape(env.url)}</a></td>"
                    f"<td>{env.status_code}</td>"
                    f"<td>{env.content_length}</td>"
                    f"<td><span class='badge {rc}'>{env.risk_level}</span></td>"
                    f"<td class='findings'>{fh}</td>"
                    f"</tr>"
                )
        # ── Page findings rows ──────────────────────────────────────────
        page_rows = ""
        for r in self.results:
            for page in r.exposed_pages:
                rc2   = {"CRITICAL":"critical","HIGH":"high","MEDIUM":"medium","LOW":"low"}.get(page.risk_level,"low")
                evh   = "".join(f"<code>{ev.replace('<','&lt;').replace('>','&gt;')}</code><br>" for ev in page.evidence[:5]) or "<em>Accessible</em>"
                safe_t = r.target.replace("<","&lt;").replace(">","&gt;")
                safe_u = html.escape(page.url, quote=True)
                page_rows += (
                    f"<tr>"
                    f"<td>{safe_t}<br><small class='src'>[{r.source}]</small></td>"
                    f"<td><a href=\"{safe_u}\" target=\"_blank\">{html.escape(page.url)}</a></td>"
                    f"<td>{page.status_code}</td>"
                    f"<td>{page.content_length}</td>"
                    f"<td><span class='badge {rc2}'>{page.risk_level}</span></td>"
                    f"<td class='findings'><b>{page.label}</b><br>{evh}</td>"
                    f"</tr>"
                )

        if not rows:
            rows = "<tr><td colspan='6' style='text-align:center;color:#6e7681'>.env scan: No exposures found.</td></tr>"
        if not page_rows:
            page_rows = "<tr><td colspan='6' style='text-align:center;color:#6e7681'>Web exposure scan: No exposures found.</td></tr>"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>RedHunter Report</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Courier New',monospace;background:#0d0d0d;color:#c9d1d9;padding:24px}}
    h1{{color:#58a6ff;text-align:center;margin-bottom:6px;font-size:1.6rem}}
    .meta{{color:#8b949e;text-align:center;margin-bottom:28px;font-size:.85rem}}
    table{{width:100%;border-collapse:collapse;font-size:.88rem}}
    th{{background:#161b22;color:#58a6ff;padding:10px 12px;border:1px solid #30363d;text-align:left}}
    td{{padding:9px 12px;border:1px solid #21262d;vertical-align:top;word-break:break-all}}
    tr:nth-child(even){{background:#0f0f0f}}
    tr:hover{{background:#1a1f27}}
    .badge{{display:inline-block;padding:3px 9px;border-radius:4px;font-weight:bold;font-size:.8rem}}
    .critical{{background:#7f1d1d;color:#fca5a5}}
    .high{{background:#78350f;color:#fcd34d}}
    .medium{{background:#1e3a5f;color:#93c5fd}}
    .low{{background:#14532d;color:#86efac}}
    .findings{{font-size:.82em;line-height:1.7}}
    .src{{color:#6e7681;font-size:.8em}}
    a{{color:#58a6ff;text-decoration:none}}
    a:hover{{text-decoration:underline}}
    code{{background:#161b22;padding:1px 4px;border-radius:3px;font-size:.85em}}
    .stats-bar{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0 24px;justify-content:center}}
    .stat{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center;min-width:90px}}
    .stat.critical{{border-color:#7f1d1d}}
    .stat.high{{border-color:#78350f}}
    .stat-val{{display:block;font-size:1.6rem;font-weight:bold;color:#58a6ff}}
    .stat.critical .stat-val{{color:#fca5a5}}
    .stat.high .stat-val{{color:#fcd34d}}
    .stat-lbl{{display:block;font-size:.75rem;color:#8b949e;margin-top:2px;text-transform:uppercase;letter-spacing:.05em}}
  </style>
</head>
<body>
  <h1>🔍 RedHunter Report</h1>
  <p class="meta">
    By {AUTHOR} | {TG_HANDLE} | Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
  </p>
  <div class="stats-bar">
    <div class="stat"><span class="stat-val">{self.stats.get("scanned",0)}</span><span class="stat-lbl">Targets Scanned</span></div>
    <div class="stat critical"><span class="stat-val">{self.stats.get("exposed",0)}</span><span class="stat-lbl">.env Exposed</span></div>
    <div class="stat high"><span class="stat-val">{self.stats.get("pages_found",0)}</span><span class="stat-lbl">Web Exposures</span></div>
    <div class="stat critical"><span class="stat-val">{self.stats.get("critical",0)}</span><span class="stat-lbl">Critical Risk</span></div>
    <div class="stat"><span class="stat-val">{self.stats.get("new_findings",0)}</span><span class="stat-lbl">New Findings</span></div>
  </div>
  <h2 style="color:#58a6ff;margin:20px 0 10px">.env File Exposures</h2>
  <table>
    <thead>
      <tr>
        <th>Target</th><th>Exposed URL</th><th>HTTP</th>
        <th>Size</th><th>Risk</th><th>Findings</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>

  <h2 style="color:#58a6ff;margin:30px 0 10px">Web Exposure Findings</h2>
  <p style="color:#8b949e;font-size:.85em;margin-bottom:12px">
    🔴 CRITICAL: Config files with credentials, SQL backups, SSH keys &nbsp;|&nbsp;
    🟠 HIGH: Git repos, DevOps files &nbsp;|&nbsp;
    🟡 MEDIUM: Login panels (phpMyAdmin, cPanel, admin) — require credentials to exploit
  </p>
  <table>
    <thead>
      <tr>
        <th>Target</th><th>Exposed URL</th><th>HTTP</th>
        <th>Size</th><th>Risk</th><th>Type / Evidence</th>
      </tr>
    </thead>
    <tbody>{page_rows}</tbody>
  </table>
</body>
</html>"""
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_content)
            console.print(f"[bold green]✔[/bold green] HTML → [cyan]{path}[/cyan]")
        except OSError as e:
            console.print(f"[red]  [!] Could not write HTML: {e}[/red]")


# ─── SCHEDULER ────────────────────────────────────────────────────────────────
class ScheduledRunner:
    """Runs RedHunter on a repeating interval. SIGINT-safe on all platforms."""

    def __init__(self, args: DefaultArgs, target_factory):
        self.args           = args
        self.target_factory = target_factory
        self._stop          = threading.Event()

    def _run_once(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        console.print(Panel(
            f"[bold cyan]◉ RedHunter Run[/bold cyan] — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            border_style="cyan"
        ))
        targets = self.target_factory()
        if not targets:
            console.print("[yellow]  No targets for this run.[/yellow]")
            return

        hunter = RedHunter(self.args)
        try:
            results  = hunter.run(targets)
            reporter = Reporter(results, hunter.stats, self.args)
            reporter.print_summary_table()
            reporter.print_findings()        # .env file exposures
            reporter.print_page_findings()   # web exposures
            reporter.print_stats()

            out_dir = self.args.output
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            base = os.path.join(out_dir, f"scheduled_{ts}")
            # Respect output flags — save only what the user asked for
            if self.args.json or self.args.all_reports: reporter.save_json(base + ".json")
            if self.args.txt  or self.args.all_reports: reporter.save_txt(base  + ".txt")
            if self.args.html or self.args.all_reports: reporter.save_html(base + ".html")
            # If no output flags set, default to saving all for scheduled runs
            if not (self.args.json or self.args.txt or self.args.html or self.args.all_reports):
                reporter.save_json(base + ".json")
                reporter.save_txt(base  + ".txt")
                reporter.save_html(base + ".html")
        except Exception as _run_err:
            console.print(f"[red]  [!] Scheduled run error: {_run_err}[/red]")
        finally:
            hunter.close()  # always drain TG queue + close DB + sessions

    def start(self, interval_hours: float):
        console.print(Panel(
            f"[bold white]Scheduler active[/bold white] — every [bold cyan]{interval_hours}h[/bold cyan]\n"
            f"Press [bold red]Ctrl+C[/bold red] to stop.",
            title="[bold cyan]◉ RedHunter Scheduler[/bold cyan]", border_style="cyan"
        ))

        # SIGINT is the only signal handler reliably supported on Windows
        original_handler = signal.getsignal(signal.SIGINT)

        def _stop_handler(sig, frame):
            self._stop.set()
            # Restore original so a second Ctrl+C force-kills
            signal.signal(signal.SIGINT, original_handler)
            _goodbye()  # show farewell banner

        signal.signal(signal.SIGINT, _stop_handler)

        # Run immediately, then schedule
        self._run_once()
        schedule.every(interval_hours).hours.do(self._run_once)

        while not self._stop.is_set():
            schedule.run_pending()
            # Sleep in small chunks so Ctrl+C is responsive
            for _ in range(6):
                if self._stop.is_set():
                    break
                time.sleep(5)


# ─── HELPERS ──────────────────────────────────────────────────────────────────
def _load_targets_file(path: str) -> List[str]:
    """Load and validate targets file. Warns on bad lines without aborting."""
    if not os.path.isfile(path):
        console.print(f"[red]  [!] File not found: {path}[/red]")
        sys.exit(1)
    from urllib.parse import urlparse as _urlparse
    valid = []
    skipped = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if " " in line or "\t" in line:
                console.print(f"[yellow]  [!] Line {lineno} skipped (whitespace in URL): {line!r}[/yellow]")
                skipped += 1
                continue
            candidate = line if "://" in line else "https://" + line
            try:
                p = _urlparse(candidate)
                if p.scheme not in ("http", "https") or not p.netloc:
                    raise ValueError("bad scheme or host")
                valid.append(line)
            except Exception:
                console.print(f"[yellow]  [!] Line {lineno} skipped (invalid URL): {line}[/yellow]")
                skipped += 1
    if skipped:
        console.print(f"[yellow]  [!] {skipped} line(s) skipped from {path}[/yellow]")
    return valid

def _print_history():
    db   = StateDB(DB_PATH)
    rows = db.get_history()
    db.close()
    if not rows:
        console.print("\n[dim]  No findings in the state database yet.[/dim]\n")
        return
    t = Table(
        title="[bold cyan]Historical Findings[/bold cyan]",
        box=box.SIMPLE_HEAVY, border_style="cyan", show_lines=True
    )
    t.add_column("Type",       justify="center",    min_width=10)
    t.add_column("URL",        style="cyan",        no_wrap=False, max_width=55)
    t.add_column("Risk",       justify="center",    min_width=8)
    t.add_column("Category / Label",  style="yellow", no_wrap=False, max_width=28)
    t.add_column("First Seen", min_width=19)
    t.add_column("Last Seen",  min_width=19)
    for row in rows:
        url, risk, cats, kind, first_seen, last_seen = row[0], row[1], row[2], row[3], row[4], row[5]
        rc = RISK_COLORS.get(risk, "white")
        # Use the 'kind' column written by mark_seen_atomic ('env') / mark_seen_page_atomic ('page')
        type_label = "[bold green].env File[/bold green]" if kind == "env" else "[bold cyan]Web Exposure[/bold cyan]"
        t.add_row(type_label, url, f"[{rc}]{risk}[/{rc}]", cats[:40], first_seen[:19], last_seen[:19])
    console.print(t)


# ─── INTERACTIVE WIZARD ───────────────────────────────────────────────────────
def interactive_wizard():
    console.print(BANNER)
    console.print(Panel(
        f"[bold white]RedHunter v{VERSION} — Web Vulnerability & Recon Framework[/bold white]\n"
        "[dim]Authorized use only. Scan only systems you own or have explicit permission to test.[/dim]",
        border_style="cyan"
    ))

    # ── Mode select ───────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ SELECT MODE ][/bold cyan]")
    console.print("  [bold white]scan[/bold white]           Scan manually provided targets")
    console.print("  [bold white]discover+scan[/bold white]  Auto-discover assets via APIs, then scan")
    console.print("  [bold white]scheduler[/bold white]      Repeat scans every N hours automatically")
    console.print("  [bold white]history[/bold white]        View all previously detected exposures")
    console.print()
    mode = Prompt.ask("  Mode", choices=["scan", "discover+scan", "scheduler", "history"], default="scan")

    if mode == "history":
        _print_history()
        return

    # ── Build args object with full defaults ──────────────────────────────────
    args = DefaultArgs()

    # ── Target input ──────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ TARGET INPUT ][/bold cyan]")
    inp = Prompt.ask("  Input method", choices=["single", "file"], default="single")
    manual_targets: List[str] = []
    if inp == "single":
        from urllib.parse import urlparse as _wup
        while True:
            raw_t = Prompt.ask("  Enter target URL (e.g. https://example.com)").strip()
            if not raw_t:
                console.print("  [yellow]  Please enter a URL.[/yellow]")
                continue
            if " " in raw_t or "\t" in raw_t:
                console.print("  [yellow]  URL cannot contain spaces.[/yellow]")
                continue
            _cand = raw_t if "://" in raw_t else "https://" + raw_t
            try:
                _pp = _wup(_cand)
                if _pp.scheme not in ("http", "https") or not _pp.netloc:
                    raise ValueError()
            except Exception:
                console.print(f"  [yellow]  Invalid URL: {raw_t!r} — try https://example.com[/yellow]")
                continue
            manual_targets.append(raw_t)
            if not Confirm.ask("  Add another target?", default=False):
                break
    else:
        fp = Prompt.ask("  Path to targets file")
        manual_targets = _load_targets_file(fp)
        console.print(f"  [green]✔ Loaded {len(manual_targets)} targets[/green]")

    # ── Discovery ─────────────────────────────────────────────────────────────
    discovery_domains: List[str] = []
    if mode in ("discover+scan", "scheduler"):
        console.print("\n[bold cyan][ ASSET DISCOVERY ][/bold cyan]")
        seed_raw = Prompt.ask(
            "  Seed domain(s) for discovery (comma-separated)\n"
            "  e.g. example.com, app.example.com"
        )
        discovery_domains = [d.strip() for d in seed_raw.split(",") if d.strip()]

        console.print("\n  [bold white]Free sources (no API key required):[/bold white]")
        args.use_crtsh        = Confirm.ask("    crt.sh  (SSL certificate transparency)", default=True)
        args.use_hackertarget = Confirm.ask("    HackerTarget subdomain search",          default=True)
        args.use_otx          = Confirm.ask("    AlienVault OTX passive DNS",             default=True)

        console.print("\n  [bold white]API-based sources:[/bold white]")
        if Confirm.ask("    Use Shodan? [requires paid API key]", default=False):
            args.shodan_key   = Prompt.ask("    Shodan API key")
            args.shodan_pages = prompt_int("    Pages to fetch (1 page ≈ 100 results) [1-10]", default=1, min_val=1, max_val=10)
            sq = Prompt.ask("    Shodan query  e.g. hostname:example.com http.status:200")
            args._shodan_queries = [sq]

        if Confirm.ask("    Use Censys? [requires API credentials]", default=False):
            args.censys_id     = Prompt.ask("    Censys API ID")
            args.censys_secret = Prompt.ask("    Censys API Secret", password=True)
            cq = Prompt.ask("    Censys query  e.g. services.http.response.headers.server: nginx")
            args._censys_queries = [cq]

    # ── Scan options ──────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ SCAN OPTIONS ][/bold cyan]")
    args.threads = prompt_int(
        "  Concurrent threads        [10=safe | 25=fast | 50=aggressive]",
        default=25, min_val=1, max_val=200
    )
    args.path_workers = prompt_int(
        "  Path workers per target   [20=default | 40=fast | 60=aggressive]",
        default=20, min_val=5, max_val=100
    )
    args.timeout = prompt_int(
        "  Request timeout (s)       [5=fast | 8=balanced | 15=thorough]",
        default=8, min_val=1, max_val=120
    )
    args.delay = prompt_float(
        "  Delay between TARGETS     [0=fast | 0.5=polite | 1=stealth]",
        default=0.0, min_val=0.0, max_val=60.0
    )
    args.redact       = Confirm.ask("  Redact secret values in all output?",        default=False)
    args.aggressive   = Confirm.ask("  Aggressive mode (check all content types)?", default=False)
    args.verbose      = Confirm.ask("  Verbose output (print each URL checked)?",   default=False)
    args.show_content = Confirm.ask("  Print raw .env content in terminal?",        default=False)

    # Vuln scan mode selection
    console.print("\n  [bold white]Vulnerability Scan:[/bold white]")
    console.print("    [bold white]off[/bold white]        Exposure scan only (no plugin CVE checks)")
    console.print("    [bold white]combined[/bold white]   Exposure scan + plugin CVE fingerprinting [recommended]")
    console.print("    [bold white]vuln-only[/bold white]  Plugin CVE fingerprinting only (skip exposure scan)")
    console.print()
    _vscan_mode = Prompt.ask(
        "  Vuln scan mode",
        choices=["off", "combined", "vuln-only"],
        default="combined"
    )
    args.vuln_scan = (_vscan_mode in ("combined", "vuln-only"))
    args.vuln_only = (_vscan_mode == "vuln-only")

    proxy_raw = Prompt.ask("  Proxy URL (leave blank to skip)  e.g. http://127.0.0.1:8080", default="")
    if proxy_raw.strip():
        px = proxy_raw.strip()
        # Auto-add http:// scheme if user typed just host:port
        if px and not px.startswith(("http://", "https://", "socks5://", "socks4://")):
            px = "http://" + px
            console.print(f"  [dim]  Proxy normalised to: {px}[/dim]")
        args.proxy = px

    # ── Telegram ──────────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ TELEGRAM ALERTS ][/bold cyan]")
    if Confirm.ask("  Enable Telegram alerts for new findings only?", default=False):
        args.tg_token = Prompt.ask("  Bot Token  (from @BotFather)")
        args.tg_chat  = Prompt.ask("  Chat ID    (your user ID or group ID)")
        notifier = TelegramNotifier(args.tg_token, args.tg_chat)
        if notifier.test_connection():
            console.print("  [bold green]✔ Telegram connection verified[/bold green]")
        else:
            console.print("  [red]  ✗ Telegram test failed — double-check your token and chat ID[/red]")

    # ── Output options ────────────────────────────────────────────────────────
    console.print("\n[bold cyan][ OUTPUT ][/bold cyan]")
    args.output  = Prompt.ask("  Output directory", default="./reports")
    args.json    = Confirm.ask("  Save JSON report?", default=True)
    args.txt     = Confirm.ask("  Save TXT report?",  default=True)
    args.html    = Confirm.ask("  Save HTML report?", default=True)

    # ── Scheduler ─────────────────────────────────────────────────────────────
    if mode == "scheduler":
        console.print("\n[bold cyan][ SCHEDULER ][/bold cyan]")
        interval = prompt_float("  Scan interval in hours  [e.g. 6, 12, 24]", default=24.0, min_val=0.1, max_val=8760.0)

        def target_factory() -> List[str]:
            t = list(manual_targets)
            if discovery_domains:
                disc = AssetDiscovery(args)
                t += disc.discover_all(
                    domains=discovery_domains,
                    shodan_queries=args._shodan_queries,
                    censys_queries=args._censys_queries,
                )
            return _dedup_targets(t)

        runner = ScheduledRunner(args, target_factory)
        runner.start(interval)
        return

    # ── Build final target list ───────────────────────────────────────────────
    all_targets = list(manual_targets)
    if mode == "discover+scan" and discovery_domains:
        disc = AssetDiscovery(args)
        all_targets += disc.discover_all(
            domains=discovery_domains,
            shodan_queries=args._shodan_queries,
            censys_queries=args._censys_queries,
        )
        all_targets = _dedup_targets(all_targets)

    if not all_targets:
        console.print("[red]  No targets to scan. Exiting.[/red]")
        return

    # ── Launch summary ────────────────────────────────────────────────────────
    console.print()
    console.print(Panel(
        f"[bold white]Total Targets :[/bold white]  {len(all_targets)}\n"
        f"[bold white]Threads       :[/bold white]  {args.threads}\n"
        f"[bold white]Path Workers  :[/bold white]  {args.path_workers}\n"
        f"[bold white]Timeout       :[/bold white]  {args.timeout}s\n"
        f"[bold white]Delay         :[/bold white]  {args.delay}s\n"
        f"[bold white]Vuln Mode     :[/bold white]  {'vuln-only' if args.vuln_only else 'combined' if args.vuln_scan else 'off'}\n"
        f"[bold white]Redact        :[/bold white]  {args.redact}\n"
        f"[bold white]Proxy         :[/bold white]  {args.proxy or 'None'}\n"
        f"[bold white]Telegram      :[/bold white]  {'✔ Enabled' if args.tg_token else '✗ Disabled'}\n"
        f"[bold white]Output dir    :[/bold white]  {args.output}",
        title="[bold red]◉ Scan Configuration[/bold red]", border_style="red"
    ))

    if not Confirm.ask("\n  [bold yellow]▶ Launch scan?[/bold yellow]", default=True):
        console.print("[dim]  Aborted.[/dim]")
        return

    hunter = RedHunter(args)
    try:
        results  = hunter.run(all_targets)
        reporter = Reporter(results, hunter.stats, args)

        reporter.print_summary_table()
        reporter.print_findings()
        reporter.print_page_findings()
        reporter.print_vuln_findings()
        reporter.print_stats()

        Path(args.output).mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(args.output, f"redhunter_{ts}")
        if args.json: reporter.save_json(base + ".json")
        if args.txt:  reporter.save_txt(base  + ".txt")
        if args.html: reporter.save_html(base + ".html")
    except KeyboardInterrupt:
        _goodbye(hunter)
        sys.exit(0)
    finally:
        hunter.close()


# ─── CLI ARG PARSER ───────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redhunter",
        description=f"RedHunter v{VERSION} — Web Vulnerability & Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"  Author: {AUTHOR}  |  Telegram: {TG_HANDLE}"
    )

    inp = p.add_argument_group("Input")
    inp.add_argument("-u", "--url",  default=None, help="Single target URL")
    inp.add_argument("-f", "--file", default=None, help="File with target URLs (one per line)")

    disc = p.add_argument_group("Asset Discovery")
    disc.add_argument("--discover",         nargs="+", metavar="DOMAIN", default=None,
                      help="Seed domains for asset discovery")
    disc.add_argument("--shodan-key",       metavar="KEY",    default=None, help="Shodan API key")
    disc.add_argument("--shodan-query",     nargs="+",        default=None, help="Shodan search queries")
    disc.add_argument("--shodan-pages",     type=int,         default=1,    help="Shodan pages (default 1)")
    disc.add_argument("--censys-id",        metavar="ID",     default=None, help="Censys API ID")
    disc.add_argument("--censys-secret",    metavar="SECRET", default=None, help="Censys API Secret")
    disc.add_argument("--censys-query",     nargs="+",        default=None, help="Censys queries")
    disc.add_argument("--no-crtsh",         action="store_true", help="Disable crt.sh")
    disc.add_argument("--no-hackertarget",  action="store_true", help="Disable HackerTarget")
    disc.add_argument("--no-otx",           action="store_true", help="Disable AlienVault OTX")

    sc = p.add_argument_group("Scan Options")
    sc.add_argument("--path-workers", type=int, default=20, metavar="N",
                    help="Path workers per target (default 20; higher=faster on live hosts)")
    sc.add_argument("-t", "--threads",   type=int,   default=25,  metavar="N",  help="Worker threads (default: 25, max recommended: 50)")
    sc.add_argument("--timeout",         type=int,   default=10)
    sc.add_argument("--delay",           type=float, default=0.0)
    sc.add_argument("--proxy",           default=None, metavar="URL")
    sc.add_argument("--aggressive",      action="store_true")
    sc.add_argument("--extra-paths",     nargs="+",  default=None)
    sc.add_argument("-H", "--headers",   nargs="+",  default=None)

    vuln = p.add_argument_group("Vulnerability Scan")
    vuln.add_argument("--vuln-scan",  action="store_true",
                      help="Enable plugin CVE fingerprinting + surface detection")
    vuln.add_argument("--vuln-only",  action="store_true",
                      help="Skip exposure scan — run vulnerability checks only")

    tg = p.add_argument_group("Telegram")
    tg.add_argument("--tg-token",  metavar="TOKEN", default=None, help="Telegram bot token")
    tg.add_argument("--tg-chat",   metavar="ID",    default=None, help="Telegram chat/group ID")
    tg.add_argument("--tg-test",   action="store_true",           help="Send test message and exit")

    sched = p.add_argument_group("Scheduler")
    sched.add_argument("--schedule", type=float, default=None, metavar="HOURS",
                       help="Run repeatedly every N hours")

    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",   default="./reports")
    out.add_argument("--json",           action="store_true")
    out.add_argument("--txt",            action="store_true")
    out.add_argument("--html",           action="store_true")
    out.add_argument("--all-reports",    action="store_true", help="Save JSON + TXT + HTML")
    out.add_argument("--redact",         action="store_true", help="Redact secret values in output")
    out.add_argument("--show-content",   action="store_true", help="Print raw .env content")
    out.add_argument("--history",        action="store_true", help="Show stored findings and exit")
    out.add_argument("-v", "--verbose",  action="store_true")
    out.add_argument("-q", "--quiet",    action="store_true")

    return p



# ─── GRACEFUL EXIT ────────────────────────────────────────────────────────────
def _goodbye(hunter=None):
    """Print farewell banner and clean up on Ctrl+C / SIGINT."""
    try:
        console.print()
        console.print(Panel(
            f"[bold cyan]Thanks for using RedHunter v{VERSION}![/bold cyan]\n"
            f"[white]Stay safe, scan responsibly.[/white]\n"
            f"[dim]— {AUTHOR}  |  {TG_HANDLE}[/dim]",
            title="[bold yellow]👋  Goodbye[/bold yellow]",
            border_style="yellow",
        ))
    except Exception:
        print(f"\n\n  👋  Thanks for using RedHunter v{VERSION}! Goodbye.\n")
    finally:
        if hunter is not None:
            try:
                hunter.close()
            except Exception:
                pass

# ─── ENTRY POINT ──────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) == 1:
        interactive_wizard()
        return

    parser = build_parser()
    parsed = parser.parse_args()

    # Merge into DefaultArgs (guarantees every attribute exists)
    args = merge_argparse(parsed)

    if not args.quiet:
        console.print(BANNER)

    # ── History ────────────────────────────────────────────────────────────────
    if args.history:
        _print_history()
        return

    # ── Telegram test ──────────────────────────────────────────────────────────
    if getattr(parsed, "tg_test", False):
        if not (args.tg_token and args.tg_chat):
            console.print("[red]  --tg-token and --tg-chat are required for --tg-test[/red]")
            sys.exit(1)
        ok = TelegramNotifier(args.tg_token, args.tg_chat).test_connection()
        console.print("  " + ("[green]✔ Telegram: Success[/green]" if ok else "[red]✗ Telegram: Failed[/red]"))
        return

    # ── Collect manual targets ─────────────────────────────────────────────────
    manual_targets: List[str] = []
    if args.url:
        manual_targets.append(args.url)
    if args.file:
        manual_targets += _load_targets_file(args.file)

    # ── Target factory ─────────────────────────────────────────────────────────
    def build_targets() -> List[str]:
        t = list(manual_targets)
        disc_domains   = args.discover or []
        shodan_queries = args._shodan_queries
        censys_queries = args._censys_queries
        if disc_domains or shodan_queries or censys_queries:
            disc = AssetDiscovery(args)
            t += disc.discover_all(
                domains=disc_domains,
                shodan_queries=shodan_queries,
                censys_queries=censys_queries,
            )
        return _dedup_targets(t)

    # ── Scheduler ─────────────────────────────────────────────────────────────
    if args.schedule:
        runner = ScheduledRunner(args, build_targets)
        runner.start(args.schedule)
        return

    # ── Single run ─────────────────────────────────────────────────────────────
    all_targets = build_targets()
    if not all_targets:
        console.print("[red]  No targets provided. Use -u <url>, -f <file>, or --discover <domain>.[/red]")
        parser.print_help()
        sys.exit(1)

    console.print(Panel(
        f"[bold white]Targets  :[/bold white] {len(all_targets)}\n"
        f"[bold white]Threads  :[/bold white] {args.threads}\n"
        f"[bold white]Path Wkrs:[/bold white] {args.path_workers}\n"
        f"[bold white]Timeout  :[/bold white] {args.timeout}s\n"
        f"[bold white]Proxy    :[/bold white] {args.proxy or 'None'}\n"
        f"[bold white]Redact   :[/bold white] {args.redact}\n"
        f"[bold white]Vuln Mode:[/bold white] {'vuln-only' if args.vuln_only else 'combined' if args.vuln_scan else 'off'}\n"
        f"[bold white]Telegram :[/bold white] {'✔' if args.tg_token else '✗'}\n"
        f"[bold white]Output   :[/bold white] {args.output}",
        title="[bold red]◉ Scan Configuration[/bold red]", border_style="red"
    ))

    hunter = RedHunter(args)
    try:
        results  = hunter.run(all_targets)
        reporter = Reporter(results, hunter.stats, args)

        if not args.quiet:
            reporter.print_summary_table()
            reporter.print_findings()
            reporter.print_page_findings()
            reporter.print_vuln_findings()
        reporter.print_stats()

        Path(args.output).mkdir(parents=True, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.join(args.output, f"redhunter_{ts}")
        if args.json: reporter.save_json(base + ".json")
        if args.txt:  reporter.save_txt(base  + ".txt")
        if args.html: reporter.save_html(base + ".html")
    except KeyboardInterrupt:
        _goodbye(hunter)
        sys.exit(0)
    finally:
        hunter.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _goodbye()
        sys.exit(0)
