"""Sidebar structure.  Items come from the Module table; this file only adds grouping and permissions."""
from apps.accounts.roles import ROLE_ADMIN

SECTIONS = [
    ("Operate", ["scanner", "scan-history"]),
    ("Investigate", ["forensics", "evidence-vault", "network", "cases"]),
    ("Report & Govern", ["reports", "audit-logs", "users", "settings"]),
]

# Modules only administrators may open (enforced again in each view).
ADMIN_ONLY = {"audit-logs", "users", "settings"}
ADMIN_ROLE = ROLE_ADMIN
