from .models import RequestLog
from datetime import datetime

class IPLogMiddleware:
    """Middleware to log IP, timestamp, and path of every request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get client IP
        ip = self.get_client_ip(request)
        path = request.path

        # Log to database
        RequestLog.objects.create(ip_address=ip, path=path)

        # Continue processing
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