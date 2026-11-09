from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from apps.scanner.lab import make_server


class Command(BaseCommand):
    help = "Start the local scanner lab target on 127.0.0.1 (requires EAGLEEYE_LAB_MODE=True)."

    def add_arguments(self, parser):
        parser.add_argument("--port", type=int, default=8001)

    def handle(self, *args, **options):
        if not settings.EAGLEEYE_LAB_MODE:
            raise CommandError("Lab mode is off. Set EAGLEEYE_LAB_MODE=True in .env first.")
        port = options["port"]
        server = make_server(port)
        base = f"http://127.0.0.1:{port}"
        self.stdout.write(self.style.SUCCESS(f"Lab target running at {base} (Ctrl+C to stop)"))
        self.stdout.write(f"Add to .env:  EAGLEEYE_LAB_TARGETS=127.0.0.1:{port}")
        for route, what in [("/weak", "insecure headers and cookies"), ("/hardened", "good configuration"),
                            ("/redirect-ok", "safe redirect"), ("/redirect-evil", "redirect to cloud-metadata IP (must be refused)"),
                            ("/redirect-loop", "endless redirect"), ("/slow", "15 s delay (timeout test)"), ("/big", "1 MB body")]:
            self.stdout.write(f"  {base}{route:<16} {what}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            self.stdout.write("\nStopping lab target.")
        finally:
            server.server_close()
