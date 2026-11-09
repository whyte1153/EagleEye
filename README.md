# EagleEye
**See Threats. Preserve Evidence. Strengthen Security.**

A Django platform for authorized vulnerability assessment, digital forensics, evidence
management and security reporting. This is **Phase 3 of 6** (foundation + vulnerability scanner + digital forensics).

> **Legal & ethical use.** Only assess systems and examine files you own or have written
> permission to test. EagleEye is built for defense and lab use. Unauthorized scanning
> is illegal in most countries.

---

## What Phase 1 contains

| Area | Status |
|---|---|
| Django project `eagleeye`, env-based config, secure defaults | Done |
| Login (futuristic HUD UI), logout, failed-login throttle | Done |
| Roles: Administrator / Investigator / Read-only reviewer | Done |
| Sidebar with all 11 navigation entries | Done |
| Dashboard fed by the database, with honest empty states | Done |
| Module overview (database-backed `Module` table) | Done |
| Audit log (append-only) + viewer | Done |
| User management (create users, change roles) | Done |
| Read-only Settings page | Done |
| **Phase 2:** scanner engine (SSRF-safe), 17 checks, findings, scan history + compare, HTML/JSON/PDF reports, lab target | Done |
| **Phase 3:** evidence upload, SHA-256/MD5 hashing, safe read-only storage, working-copy analysis, signature-based type detection with extension-mismatch warnings, notes, hash-chained chain of custody, integrity verification, CSV/JSON/HTML/PDF exports | Done |
| Automated tests (259) | The pure-Python engines (scanner 60 + forensics 46 + network 27) were run during development; Django-side tests must be run by you (see below) |
| Network analysis, cases, reports | Later phases (pages say so plainly) |

Nothing on the dashboard is simulated. Metrics owned by modules that do not exist yet
(assessments, findings, cases, evidence) show "available in phase N" instead of fake zeros.

## Directory structure

```
eagleeye/                  <- project root (run commands here)
├── manage.py              Django's command-line tool
├── requirements.txt       Python dependencies
├── .env.example           Copy to .env and edit
├── eagleeye/              Project package: settings.py, urls.py, wsgi.py, asgi.py
├── apps/
│   ├── core/              Dashboard, module catalogue, settings page, error pages
│   ├── accounts/          Profile (role), login view, throttle, user management, RBAC helpers
│   ├── audit/             AuditEvent model (append-only), log_event(), viewer
│   ├── network_analysis/  Phase 4
│   │   ├── engine/        PURE PYTHON: limits.py, rules.py, nmap_parser.py, pcap_reader.py, decode.py, pcap_analyzer.py
│   │   ├── models.py      NetworkImport, NetworkHost
│   │   └── services.py, views.py, forms.py, urls.py
│   ├── forensics/         Phase 3
│   │   ├── engine/        PURE PYTHON: sanitize.py, hashing.py, storage.py, filetype.py, custody.py
│   │   ├── models.py      EvidenceItem, EvidenceNote, CustodyEvent
│   │   └── services.py, views.py, forms.py, reports.py
│   └── scanner/           Phase 2
│       ├── engine/        PURE PYTHON (no Django): ssrf.py, fetcher.py, checks.py, scanner.py
│       ├── lab.py         local lab target server (weak / hardened pages)
│       ├── reports.py     JSON / HTML / PDF renderers
│       ├── models.py      Scan, Finding        services.py  engine <-> database glue
│       └── views.py, forms.py, urls.py, management/commands/lab_server.py
├── templates/             HTML (base layouts, login, dashboard, ...)
├── static/                css/eagleeye.css (HUD theme), js/eagleeye.js
├── evidence_store/        created on first upload (git-ignored; keep OUTSIDE web roots)
└── logs/                  eagleeye.log (git-ignored)
```

How the pieces fit: a browser request hits `eagleeye/urls.py`, which hands it to an app's
`urls.py`, which calls a function in `views.py`. The view reads/writes **models**
(database tables) and renders a **template**. `migrations/` files describe the tables.

## Requirements
- Kali Linux (any recent version), Python 3.12+ (Django 6.x) or 3.10+ (Django 5.2 LTS)
- Internet access once, to install Django and (optionally) load Bootstrap from a CDN

## Setup on Kali Linux

Run every command from the `eagleeye/` folder (the one containing `manage.py`).

```bash
# 1. Unpack and enter the project
unzip eagleeye-phase1.zip
cd eagleeye

# 2. Create an isolated Python environment (keeps packages out of the system Python)
sudo apt install -y python3-venv      # only if venv is missing
python3 -m venv .venv
source .venv/bin/activate             # prompt now starts with (.venv)

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create your local config
cp .env.example .env
```

Edit `.env` (e.g. `nano .env`). For local work set `EAGLEEYE_DEBUG=True`. Generate a real key with:

```bash
python -c "from django.core.management.utils import get_random_secret_key as k; print(k())"
```
and paste it as `EAGLEEYE_SECRET_KEY=...`. With `DEBUG=False` the app refuses to start without a real key.

```bash
# 5. Create the database tables (also seeds the 10 module rows)
python manage.py migrate

# 6. Create your administrator account (choose a password of 12+ characters)
python manage.py createsuperuser

# 7. Run the automated tests
python manage.py test

# 8. Start the server
python manage.py runserver
```

**Expected output**
- `migrate`: lines like `Applying accounts.0001_initial... OK`, `Applying core.0002_seed_modules... OK`, `Applying audit.0001_initial... OK`.
- `test`: `Found 259 test(s)` ... `Ran 259 tests` ... `OK`.
- `runserver`: `Starting development server at http://127.0.0.1:8000/`.

Open **http://127.0.0.1:8000/** and sign in with the account from step 6.

## Phase 2: the vulnerability scanner

### What it checks (17 checks; each finding explains itself and gives a `curl`/`openssl` command to reproduce it)
| Area | Checks |
|---|---|
| Transport | HTTPS used; HTTPS->HTTP downgrade in redirects; http:// redirects to https://; redirect chain length/loops; redirects to unapproved hosts (not followed) |
| TLS | Negotiated version; certificate verification (expired / wrong host / untrusted); days until expiry |
| Headers | Content-Security-Policy (missing / weak); Strict-Transport-Security (missing / short); X-Content-Type-Options; X-Frame-Options or CSP `frame-ancestors`; Referrer-Policy; Permissions-Policy; version leaks in `Server` / `X-Powered-By` |
| Cookies | `Secure`, `HttpOnly`, `SameSite` on every `Set-Cookie` (cookie **values are discarded**, never stored) |
| Response | Status code, slow responses, body-size limit reached |

Severities: Informational, Low, Medium, High, Critical. **No current check produces Critical**, because configuration checks cannot prove a critical flaw; the level is reserved for future checks. Only the *negotiated* TLS version is tested, not whether older versions are also accepted. Application flaws (injection, access control, outdated software) are **not** tested, and a clean report does not mean a site is secure.

### How SSRF is prevented
1. Only `http`/`https`; no credentials in URLs; length and character limits.
2. **Targets are entered on the Scanner page** (no allowlist in `.env`). Each scan requires you to confirm authorization, and that confirmation, your optional reference and your user name are saved and audited. Safety comes from the rules below, not from a host list.
3. Ports are limited (default 80, 443, 8080, 8443).
4. EagleEye does the DNS lookup itself and rejects the target if **any** returned address is private, loopback, link-local, multicast, reserved or carrier-grade NAT. Obfuscated forms (`2130706433`, `0x7f.1`, `::ffff:127.0.0.1`) are judged by the address they resolve to.
5. It then connects **to that validated IP** (keeping the real `Host` header and TLS server name), so no second lookup can return an internal address: this defeats DNS rebinding.
6. Redirects are followed manually; every hop repeats steps 1-5. An unapproved destination is recorded but never contacted.
7. Cloud-metadata addresses and names (`169.254.169.254`, `metadata.google.internal`, ...) are refused even in lab mode.

Other limits: per-request timeout, overall deadline, 256 KB body cap, at most 5 redirects, 10 scans per user per 10 minutes, 3 scans at a time. Scans run inside the web request (simple and bounded by the deadline); no background worker is needed yet.

### Safe local testing with the lab target
```bash
# 1. In .env set:
#      EAGLEEYE_LAB_MODE=True
#      EAGLEEYE_LAB_TARGETS=127.0.0.1:8001
# 2. Terminal A: start the deliberately weak lab server (127.0.0.1 only)
python manage.py lab_server
# 3. Terminal B: start EagleEye (restart it after editing .env)
python manage.py runserver
```
Sign in as an administrator or investigator, open **Vulnerability Scanner**, and scan:

| URL | What to expect |
|---|---|
| `http://127.0.0.1:8001/weak` | HIGH (plain HTTP), missing CSP / clickjacking protection, insecure cookies, version leak... |
| `http://127.0.0.1:8001/hardened` | Only the plain-HTTP and `Server` version findings remain |
| `http://127.0.0.1:8001/redirect-evil` | Redirect to `169.254.169.254` is **not followed** (Informational finding) |
| `http://127.0.0.1:8001/slow` | Scan fails with "timed out" |
| `http://127.0.0.1:8001/redirect-loop` | "Too many redirects" |
| `http://127.0.0.1:9999/` | **Blocked**: not a listed lab target |

Scan `/weak`, then `/hardened`, open **Scan History**, tick both and press *Compare* to see resolved/new findings. Use the HTML / JSON / PDF buttons on a scan to download reports (generated from saved data). To scan a real site you own, open **Vulnerability scanner**, type its address (for example `https://www.example.com/`), tick the authorization box and run it. Nothing needs to be configured in `.env`.

### Tests for Phase 2
| Type | File | Notes |
|---|---|---|
| Unit | `scanner/tests/test_engine.py` (checks, URL normalisation, allowlist, private-IP/metadata blocking, obfuscated IPs, injected DNS) | no network |
| Integration | same file: lab server on loopback, real sockets: redirects, loops, timeouts, size cap, malformed/garbage responses, self-signed HTTPS | local only |
| Integration | `scanner/tests/test_views.py` (permissions, CSRF, persistence, rate/concurrency limits, history, compare, reports, XSS escaping, audit) | Django test client |
| Manual | Lab target walkthrough above | |

The engine has no Django dependency, so it can be tested alone: `python -m unittest apps.scanner.tests.test_engine -v` (needs only `openssl` on PATH for the TLS test, which is skipped otherwise).

## Phase 3: digital forensics and the evidence vault

### How a file is handled
1. **Upload** (administrator / investigator): the file streams to a temporary file on disk (never held in memory), and the request is rejected up front if its declared size exceeds the limit (`EAGLEEYE_EVIDENCE_MAX_MB`, default 100).
2. **Hashed while written**: SHA-256 (the integrity hash) and MD5 (legacy identification only) are computed as the bytes are saved.
3. **Preserved**: stored in `evidence_store/originals/ab/<random 32-hex name>` with mode `0440`, in a private (`0700`) directory **outside** any web-served folder. The name the uploader chose is cleaned (path parts, control and bidi-override characters removed) and used for display only. EagleEye refuses to start the store inside `static/`, `templates/` and similar directories. There is no public URL to evidence: every download goes through an authenticated view.
4. **Analysed on a working copy**: a private copy is made and proven identical by hash before analysis, then deleted. The original is never opened for writing; EagleEye has no code path that modifies or deletes evidence (the model layer and Django admin refuse deletes).
5. **Type check**: the content signature (magic bytes) is compared with the file extension. Findings: *match*, *info*, *warn* (renamed or mismatched file) and *high* (an executable or script wearing a document/image extension). Office, Java and Android packages are recognised inside ZIP containers and archive entries are listed (never extracted, with path-traversal names flagged). Detection covers a limited set of common formats and says "unrecognised" rather than guessing.
6. **Custody**: every action (upload, analysis, verification, download, note, report export) is a **hash-chained** custody event: each entry stores the SHA-256 of the previous entry plus its own fields. Edit, delete or re-order any entry, even directly in the database, and the vault shows **HASH CHAIN BROKEN**. Limitation: someone who can rewrite the *whole* table consistently, or silently drop the newest entries, is not detectable; keep the latest chain hash in an external record (e.g. in your case notes or the exported PDF).
7. **Verification**: *Verify integrity* re-hashes the stored original and compares it with the SHA-256 recorded at upload (also done automatically before every download). A mismatch or missing file is marked FAILED/MISSING, logged in the custody chain, and blocks download and analysis.

### Roles
Administrators and investigators can upload, verify, re-analyse, annotate and download. **Reviewers** can see the vault, details and exports but cannot download raw files (they may be malware) or change anything.

### Try it (hash-verification walkthrough)
```bash
echo "case file contents" > sample.txt
sha256sum sample.txt            # note this value
```
1. **Digital Forensics -> Add evidence**: choose `sample.txt`, tick the authorization box, *Hash & preserve*. The detail page shows the **same SHA-256**.
2. Press *Verify integrity*: "matches its recorded SHA-256". Press *Download original* and run `sha256sum` on the download: identical again.
3. Simulate tampering (as the user running the server; the file is read-only so make it writable first). The stored path is under `evidence_store/originals/<2 chars>/<name>`:
   ```bash
   chmod u+w evidence_store/originals/*/*
   echo "x" >> evidence_store/originals/*/*      # appends a byte to the stored file
   ```
   Press *Verify integrity*: **INTEGRITY FAILED**, the download button now refuses, and the custody log shows `integrity_failed` with the expected and actual hashes.
4. Rename a copy of any program, e.g. `cp /bin/ls holiday.jpg`, and upload it: flagged **Extension: HIGH** ("Possible disguised executable"). It is stored but never run.
5. Open **Evidence Vault**, filter by integrity or search by hash, then export the **Inventory CSV** and the **Integrity report** (HTML / PDF / JSON), or a single **Evidence record** with its full custody chain. CSV cells that start with `=`, `+`, `-` or `@` are prefixed so spreadsheets cannot run them as formulas.

### What the hashes do and do not prove
A matching SHA-256 shows the stored copy is bit-identical to what EagleEye received. It does not show the evidence was unaltered before upload, and file timestamps and other metadata can be changed by acquisition and upload (browsers do not send the original timestamps, so EagleEye shows the timestamps of its own stored copy, labelled as such). Entropy figures are informational only.

### Tests for Phase 3
| Type | File | Notes |
|---|---|---|
| Unit | `forensics/tests/test_engine.py` (46): file-name sanitising, hash vectors, streaming ingest, size limit and cleanup, traversal-proof names, read-only storage, symlink refusal, tamper/missing detection, working copies, signature detection and mismatch matrix, ZIP listing, custody-chain edit/delete/re-order detection, scripts never executed | pure Python; run `python -m unittest apps.forensics.tests.test_engine -v` |
| Integration | `forensics/tests/test_views.py`: permissions and CSRF, upload rules, hostile names, escaping, evidence-root safety, integrity failure blocking download, custody and DB-level tampering, notes immutability, downloads, exports, vault filters, dashboard, request-size middleware | Django test client with a temp evidence store |
| Manual | Walkthrough above | |

## Phase 4: network analysis (Nmap XML and PCAP)

Open **Network analysis** in the sidebar (`/network/`). Import results from networks you are authorized to assess; EagleEye reads and summarises them. **It never runs Nmap or any scan, never captures traffic, and never executes imported files.**

### Get data on Kali

```bash
# Nmap (only against a network you own or are authorized to test, e.g. a VirtualBox host-only lab)
nmap -sV -oX scan.xml 192.168.56.0/24
# Packet capture (stop with Ctrl+C)
sudo tcpdump -i eth0 -w capture.pcap
```

### What you get

| Import | Output |
|---|---|
| Nmap XML | Hosts, open ports, services/versions, OS guess, and **risky-service indicators** with a reason and a suggested fix |
| PCAP / PCAPNG | Packet/byte totals, time range, protocol counts, top talkers, TCP/UDP flows, DNS names, and indicators |

Search and filter by host, port, service, severity (Nmap) or by IP, port, protocol, text (PCAP). Export **CSV** and **JSON** (filters apply). CSV cells beginning with `= + - @` are neutralised against spreadsheet formula injection.

### Transparent rules (no hidden scoring)

Every flag comes from a readable rule in `apps/network_analysis/engine/rules.py` (service name, with port only as a fallback when Nmap could not identify the service) or `pcap_analyzer.py`:

- **High:** Telnet, r-services (rsh/rlogin/rexec), exposed Docker API, anonymous FTP (from the `ftp-anon` script).
- **Medium:** FTP, TFTP, SMB, RDP, VNC, SNMP, NFS/RPC, X11, AJP, exposed databases, cleartext mail; SMB signing disabled.
- **Low/Info:** plain HTTP/LDAP, SSH (informational).
- **PCAP:** a source sending SYN-only packets to 20+ ports of one host (possible port scan) or to 20+ hosts (possible sweep); cleartext protocols carrying data (Telnet, FTP, HTTP, POP3, IMAP, SMTP, SNMP, TFTP); unusually long DNS labels.

These are **indicators for a human to review, not proof** of a vulnerability or an attack. An open port is not a vulnerability, and a closed or filtered port is never flagged.

### Safety limits

- Type is detected from file **content**, not name. Compressed files are refused.
- Nmap XML: DOCTYPE with an internal subset, `ENTITY`/`ELEMENT`/`ATTLIST` declarations or external references are rejected (stops entity-expansion and XXE); limits on XML elements, nesting depth, hosts and ports.
- PCAP: every length field is checked; oversize or truncated records are rejected; limits on packets, flows, IPs, DNS names and a time budget. When a limit is hit, you get a **warning** and partial results, never a silent cut-off.
- **Packet payloads are never stored.** Only headers-derived summaries are kept.
- The upload is parsed in its temporary location and then discarded; only parsed results and the file's SHA-256 are stored. Put the original in the **Evidence Vault** if you need chain of custody.
- Imports cannot be deleted through EagleEye; import, rejection and export events go to the audit log.
- Roles: admins and investigators import; reviewers view and export.

Limits are configurable in `.env` (`EAGLEEYE_NETWORK_MAX_MB`, `_MAX_HOSTS`, `_MAX_PACKETS`, `_DEADLINE_SECONDS`).

### Why custom parsers instead of Scapy/PyShark

The parsers are small, dependency-free and bounded. That keeps the attack surface small (no Wireshark/tshark dissectors run on hostile input) and makes limits explicit. The trade-off: only Ethernet, raw IP, Linux cooked and loopback captures; IPv4/IPv6, TCP, UDP, ICMP, ARP and DNS names are decoded; no TCP stream reassembly, no TLS decryption, no application-layer dissection. Use Wireshark for deeper analysis.

### Tests for Phase 4

`python -m unittest apps.network_analysis.tests.test_engine -v` runs the 27 engine tests (rules, Nmap parsing and attack rejection, limits, classic PCAP little/big-endian, PCAPNG, truncated/hostile files, filters) without Django. `apps/network_analysis/tests/test_views.py` covers permissions, upload safety, filtering, exports, audit and escaping via the Django test client.

## Using Phase 1
- **Dashboard** - hero panel, metric cards, 7-day audit activity chart (real data), module overview, recent audit events.
- **User Management** (admin) - create an *Investigator* and a *Reviewer* account, sign in as each and notice the sidebar changes and admin pages return "Access denied".
- **Audit Logs** (admin) - every sign-in, failed sign-in, logout, user creation and role change. Records cannot be edited or deleted via the app.
- **Settings** (admin) - read-only security configuration. No secrets are shown.
- Planned modules open an honest "arrives in phase N" page listing their planned capabilities.

## Tests
| Type | Where | Notes |
|---|---|---|
| Unit | `apps/audit/tests` (append-only model, helper), `apps/core/tests` (catalogue, chart data) | No browser/network |
| Integration | `apps/accounts/tests` (login, lockout, CSRF, RBAC, user admin) | Django test client + test database |
| Manual | Visual check on desktop and phone width; keyboard-only navigation | Described above |

`python manage.py test apps.accounts` runs a single app.

## Security notes (Phase 1)
- Secrets come from environment variables; `.env` is git-ignored.
- Passwords: 12+ characters, common/numeric passwords rejected, hashed by Django.
- Login throttle: 5 failures per IP or username -> 5-minute lockout (per-process cache; use a shared cache in production).
- CSRF on every form; logout is POST-only; output auto-escaped; `X-Frame-Options: DENY`; nosniff; same-origin referrer policy.
- With `DEBUG=False`: secure cookies, HTTPS redirect and HSTS are enabled; error pages never show internals.
- Scanner: see *How SSRF is prevented*. Scan reports and the database never contain cookie values.
- **Known gap:** the built-in `/admin/` site is not covered by the login throttle. It is for administrators only; Phase 6 hardening will address it (and add a Content-Security-Policy).
- Bootstrap is loaded from jsDelivr. The theme CSS works without it; to self-host, download Bootstrap into `static/vendor/` and edit the `<link>` in `templates/base_public.html`.
- Fonts are system fonts only: no third-party font requests.

## Production deployment notes (so far)
- Put the evidence store on its own protected, backed-up volume (`EAGLEEYE_EVIDENCE_ROOT`), readable only by the application user.
- Set the same upload limit in the reverse proxy (nginx: `client_max_body_size 100m;`), run behind HTTPS, and keep `DEBUG=False`.
- Back up the database **and** the evidence store together; hashes in the database are what prove the files unchanged.

## Troubleshooting
| Problem | Fix |
|---|---|
| `ImproperlyConfigured: Set EAGLEEYE_SECRET_KEY` | Create `.env` (step 4) and set `EAGLEEYE_DEBUG=True` or a real key |
| `No module named django` | `source .venv/bin/activate` then `pip install -r requirements.txt` |
| `no such table` | Run `python manage.py migrate` |
| `UnsafeStorage: Evidence root ... must not be inside` | Set `EAGLEEYE_EVIDENCE_ROOT` to a folder outside `static/`, `templates/` and the project package |
| Upload returns 413 | File exceeds `EAGLEEYE_EVIDENCE_MAX_MB` (or the reverse-proxy limit) |
| Permission denied when tampering demo | Evidence files are read-only on purpose: `chmod u+w` first |
| Scan is "Blocked: resolves to a non-public address" | Private, loopback and metadata addresses are always refused. For your own local test server use lab mode (below) |
| Scan is "Port N is not permitted" | Add the port to `EAGLEEYE_SCAN_ALLOWED_PORTS` (default 80,443,8080,8443) and restart |
| Lab scan blocked for port | `EAGLEEYE_LAB_TARGETS` must match host **and** port, and `EAGLEEYE_LAB_MODE=True` |
| `DisallowedHost` | Add the host to `EAGLEEYE_ALLOWED_HOSTS` |
| Page looks unstyled | Check the browser console; `static/css/eagleeye.css` must load |
| Migration warning about model changes | Run `python manage.py makemigrations` and re-run `migrate` |

## Roadmap
1. **Phase 1** - foundation (done)
2. ~~Phase 2 - scanner engine, SSRF protection, findings, scan history~~ (done)
3. ~~Phase 3 - forensics: hashing, metadata, evidence integrity~~ (done)
4. ~~Phase 4 - Nmap XML and PCAP analysis~~ (this release)
5. Phase 5 - cases, expanded audit, reports
6. Phase 6 - full test suite, hardening, deployment docs
