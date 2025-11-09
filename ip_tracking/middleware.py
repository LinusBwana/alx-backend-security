from django.http import HttpResponseForbidden
from django.core.cache import cache
from ip2geotools.databases.noncommercial import DbIpCity
from .models import RequestLog, BlockedIP

class IPLogMiddleware:
    """Middleware to log IPs, block blacklisted IPs, and store geolocation."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip = self.get_client_ip(request)
        path = request.path

        # Block blacklisted IPs
        if BlockedIP.objects.filter(ip_address=ip).exists():
            return HttpResponseForbidden("Your IP is blocked from accessing this site.")

        # Get geolocation info (cached)
        geo_data = self.get_geolocation(ip)

        # Log request
        RequestLog.objects.create(
            ip_address=ip,
            path=path,
            country=geo_data.get('country'),
            city=geo_data.get('city')
        )

        return self.get_response(request)

    def get_client_ip(self, request):
        """Extract client IP."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')

    def get_geolocation(self, ip):
        """Fetch and cache geolocation data for 24 hours."""
        cache_key = f"geo_{ip}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        try:
            # Get data using ip2geotools
            response = DbIpCity.get(ip, api_key='free')
            geo_data = {
                'country': response.country,
                'city': response.city
            }
        except Exception:
            # Fallback if lookup fails or localhost
            geo_data = {'country': None, 'city': None}

        # Cache for 24 hours (86400 seconds)
        cache.set(cache_key, geo_data, timeout=86400)
        return geo_data