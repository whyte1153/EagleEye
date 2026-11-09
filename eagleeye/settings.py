"""
EagleEye settings.

Configuration comes from environment variables (optionally loaded from a local
``.env`` file).  Nothing secret is stored in this file.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Tiny .env loader (no extra dependency).  Real environment variables win.
# ---------------------------------------------------------------------------
def _load_dotenv(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / ".env")


def env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Core security settings
# ---------------------------------------------------------------------------
DEBUG = env_bool("EAGLEEYE_DEBUG", False)

SECRET_KEY = os.environ.get("EAGLEEYE_SECRET_KEY", "")
if not SECRET_KEY or SECRET_KEY == "change-me":
    if DEBUG:
        # Local development convenience only.  Never used when DEBUG is off.
        SECRET_KEY = "dev-only-insecure-key-do-not-use-in-production"
    else:
        from django.core.exceptions import ImproperlyConfigured

        raise ImproperlyConfigured(
            "Set EAGLEEYE_SECRET_KEY in your environment or .env file "
            "(see .env.example)."
        )

ALLOWED_HOSTS = env_list("EAGLEEYE_ALLOWED_HOSTS", "127.0.0.1,localhost")
CSRF_TRUSTED_ORIGINS = env_list("EAGLEEYE_CSRF_TRUSTED_ORIGINS")


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # EagleEye apps
    "apps.core",
    "apps.accounts",
    "apps.audit",
    "apps.scanner",
    "apps.forensics",
    "apps.network_analysis",
    "apps.cases",
    "apps.reports",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "apps.core.middleware.RequestSizeLimitMiddleware",  # rejects oversized bodies before they are read
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "eagleeye.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "apps.core.context_processors.navigation",
            ],
        },
    },
]

WSGI_APPLICATION = "eagleeye.wsgi.application"
ASGI_APPLICATION = "eagleeye.asgi.application"


# ---------------------------------------------------------------------------
# Database: SQLite for development, PostgreSQL when configured
# ---------------------------------------------------------------------------
if os.environ.get("EAGLEEYE_DB_ENGINE", "sqlite").lower() in {"postgres", "postgresql"}:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("EAGLEEYE_DB_NAME", "eagleeye"),
            "USER": os.environ.get("EAGLEEYE_DB_USER", ""),
            "PASSWORD": os.environ.get("EAGLEEYE_DB_PASSWORD", ""),
            "HOST": os.environ.get("EAGLEEYE_DB_HOST", "127.0.0.1"),
            "PORT": os.environ.get("EAGLEEYE_DB_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "core:dashboard"
LOGOUT_REDIRECT_URL = "accounts:login"

# Failed-login throttle (see apps/accounts/throttle.py)
LOGIN_MAX_ATTEMPTS = env_int("EAGLEEYE_LOGIN_MAX_ATTEMPTS", 5)
LOGIN_LOCKOUT_SECONDS = env_int("EAGLEEYE_LOGIN_LOCKOUT_SECONDS", 300)


# ---------------------------------------------------------------------------
# Sessions, cookies, headers
# ---------------------------------------------------------------------------
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_AGE = 60 * 60 * 8  # 8 hours
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
X_FRAME_OPTIONS = "DENY"
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024  # 5 MB for non-file request bodies

if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = env_bool("EAGLEEYE_SSL_REDIRECT", True)
    SECURE_HSTS_SECONDS = 60 * 60 * 24 * 30
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True


# ---------------------------------------------------------------------------
# Internationalisation
# ---------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True


# ---------------------------------------------------------------------------
# Static files
# ---------------------------------------------------------------------------
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"


# ---------------------------------------------------------------------------
# Logging (errors go to the log file, never to the user)
# ---------------------------------------------------------------------------
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "{asctime} {levelname} {name}: {message}", "style": "{"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
        "file": {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": str(LOG_DIR / "eagleeye.log"),
            "maxBytes": 2 * 1024 * 1024,
            "backupCount": 3,
            "formatter": "standard",
        },
    },
    "root": {"handlers": ["console", "file"], "level": "INFO"},
}


# ---------------------------------------------------------------------------
# EagleEye-specific settings (used by later phases)
# ---------------------------------------------------------------------------
EAGLEEYE_LAB_MODE = env_bool("EAGLEEYE_LAB_MODE", False)
# Scanner (Phase 2).  Targets are entered on the web form; there is no host allowlist.
EAGLEEYE_LAB_TARGETS = env_list("EAGLEEYE_LAB_TARGETS")  # "host" or "host:port"; only used when LAB_MODE is on
SCAN_ALLOWED_PORTS = [int(p) for p in env_list("EAGLEEYE_SCAN_ALLOWED_PORTS", "80,443,8080,8443") if p.isdigit()]
SCAN_RATE_LIMIT = env_int("EAGLEEYE_SCAN_RATE_LIMIT", 10)  # scans per user per 10 minutes
SCAN_MAX_CONCURRENT = env_int("EAGLEEYE_SCAN_MAX_CONCURRENT", 3)  # scans running at once per server process
SCAN_TIMEOUT_SECONDS = env_int("EAGLEEYE_SCAN_TIMEOUT_SECONDS", 8)  # per request
SCAN_DEADLINE_SECONDS = env_int("EAGLEEYE_SCAN_DEADLINE_SECONDS", 30)  # whole scan
SCAN_MAX_BODY_BYTES = env_int("EAGLEEYE_SCAN_MAX_BODY_BYTES", 262_144)
# Evidence (Phase 3).  The store must live OUTSIDE every web-served directory.
EVIDENCE_ROOT = Path(os.environ.get("EAGLEEYE_EVIDENCE_ROOT") or (BASE_DIR / "evidence_store"))
EVIDENCE_MAX_BYTES = env_int("EAGLEEYE_EVIDENCE_MAX_MB", 100) * 1024 * 1024
# Network analysis (Phase 4): imports are parsed in place and never executed.
NETWORK_MAX_BYTES = env_int("EAGLEEYE_NETWORK_MAX_MB", 100) * 1024 * 1024
NETWORK_MAX_HOSTS = env_int("EAGLEEYE_NETWORK_MAX_HOSTS", 5000)
NETWORK_MAX_PACKETS = env_int("EAGLEEYE_NETWORK_MAX_PACKETS", 500_000)
NETWORK_DEADLINE_SECONDS = env_int("EAGLEEYE_NETWORK_DEADLINE_SECONDS", 60)
REQUEST_MAX_BYTES = 2 * 1024 * 1024  # any non-upload request body
# Always stream uploads to a temporary file on disk (never hold evidence in memory).
FILE_UPLOAD_HANDLERS = ["django.core.files.uploadhandler.TemporaryFileUploadHandler"]
FILE_UPLOAD_PERMISSIONS = 0o600
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o700
EAGLEEYE_TAGLINE = "See Threats. Preserve Evidence. Strengthen Security."
