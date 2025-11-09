from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

class IPLogMiddleware:
    """Middleware to log IP and block blacklisted addresses."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)
        path = request.path

        # Check if IP is blocked
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP is blocked from accessing this site.")

        # Log the request
        RequestLog.objects.create(ip_address=ip, path=path)

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """Extracts client IP from headers."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
