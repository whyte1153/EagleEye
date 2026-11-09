"""Seed the module catalogue shown in the sidebar and on the dashboard."""
from django.db import migrations

MODULES = [
    # slug, name, summary, icon, phase, status, url_name, features
    ("scanner", "Vulnerability Scanner",
     "Authorized web-target assessment: HTTPS, security headers, cookies, redirects and TLS.",
     "scanner", 2, "planned", "",
     ["URL validation and allowlist enforcement",
      "SSRF protection with DNS re-validation on every redirect hop",
      "Security-header and cookie-attribute checks with severities",
      "Findings with impact and remediation guidance",
      "HTML / JSON / PDF report export"]),
    ("scan-history", "Scan History",
     "Stored scan results with side-by-side comparison of previous runs.",
     "history", 2, "planned", "",
     ["Searchable history of every scan", "Compare two scans to see what changed",
      "Severity trends over time"]),
    ("forensics", "Digital Forensics",
     "Hashing, metadata extraction and integrity verification for authorized evidence files.",
     "forensics", 3, "planned", "",
     ["Safe evidence upload (stored outside the web root)",
      "SHA-256 (and optional MD5) hashing", "Extension vs detected-type mismatch checks",
      "Integrity re-verification against recorded hashes"]),
    ("evidence-vault", "Evidence Vault",
     "Evidence inventory with unique IDs, chain-of-custody notes and access control.",
     "vault", 3, "planned", "",
     ["Unique evidence identifiers", "Append-only evidence history",
      "Investigator notes and case references", "Inventory and integrity report export"]),
    ("network", "Network Analysis",
     "Defensive analysis of imported Nmap XML and PCAP files from authorized lab networks.",
     "network", 4, "planned", "",
     ["Nmap XML import with transparent risky-service rules",
      "PCAP summaries: protocols, endpoints, timestamps",
      "Search, filter and export", "Strict file-size and parsing limits"]),
    ("cases", "Investigation Cases",
     "Case and incident management tying together scans, evidence and findings.",
     "cases", 5, "planned", "",
     ["Unique case IDs and status tracking", "Related scans and evidence",
      "Chronological activity timeline", "Printable case reports"]),
    ("reports", "Reports",
     "Professional reports generated from real saved data.",
     "reports", 5, "planned", "",
     ["HTML, JSON and PDF output", "Case and scan reports", "Evidence integrity reports"]),
    ("audit-logs", "Audit Logs",
     "Append-only history of sign-ins, user changes and (later) evidence actions.",
     "audit", 1, "ready", "audit:list",
     ["Filter by action", "Search actor, target and detail"]),
    ("users", "User Management",
     "Create users and assign administrator, investigator or reviewer roles.",
     "users", 1, "ready", "accounts:users",
     ["Role-based access control", "Password validation"]),
    ("settings", "Settings",
     "Read-only view of the security configuration currently in effect.",
     "settings", 1, "ready", "core:settings",
     ["Environment-driven configuration"]),
]


def seed(apps, schema_editor):
    Module = apps.get_model("core", "Module")
    for order, (slug, name, summary, icon, phase, status, url_name, features) in enumerate(MODULES, start=1):
        Module.objects.update_or_create(
            slug=slug,
            defaults={
                "name": name, "summary": summary, "icon": icon, "phase": phase,
                "status": status, "url_name": url_name, "order": order,
                "features": "\n".join(features),
            },
        )


def unseed(apps, schema_editor):
    apps.get_model("core", "Module").objects.filter(slug__in=[m[0] for m in MODULES]).delete()


class Migration(migrations.Migration):

    dependencies = [("core", "0001_initial")]

    operations = [migrations.RunPython(seed, unseed)]
