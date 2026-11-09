from django.conf import settings
from django.http import HttpResponse


class RequestSizeLimitMiddleware:
    """Reject requests whose declared body is too large BEFORE Django reads them.

    Evidence uploads (under /forensics/) may be up to EVIDENCE_MAX_BYTES and network imports (under /network/)
    up to NETWORK_MAX_BYTES (+1 MB for the form);
    every other request body is limited to REQUEST_MAX_BYTES.  Reverse proxies should
    enforce the same limits (see README: production deployment).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                length = int(request.META.get("CONTENT_LENGTH") or 0)
            except ValueError:
                return HttpResponse("Bad Content-Length.", status=400, content_type="text/plain")
            limit = settings.REQUEST_MAX_BYTES
            if request.path.startswith("/forensics/"):
                limit = settings.EVIDENCE_MAX_BYTES + 1024 * 1024
            elif request.path.startswith("/network/"):
                limit = settings.NETWORK_MAX_BYTES + 1024 * 1024
            if length > limit:
                return HttpResponse("Request body too large.", status=413, content_type="text/plain")
        return self.get_response(request)
