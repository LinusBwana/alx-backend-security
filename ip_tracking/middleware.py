from django.http import HttpResponseForbidden
from django.core.cache import cache
from geoip2.database import Reader
from .models import RequestLog, BlockedIP
import os

# Load the GeoLite2-City database
GEOIP_DB_PATH = os.path.join(os.path.dirname(__file__), 'GeoLite2-City.mmdb')

class IPLogMiddleware:
    """Middleware to log IPs, block blacklisted IPs, and store geolocation."""

    def __init__(self, get_response):
        self.get_response = get_response
        # Initialize the geoip2 reader once
        if os.path.exists(GEOIP_DB_PATH):
            self.geo_reader = Reader(GEOIP_DB_PATH)
        else:
            self.geo_reader = None

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
        """Fetch and cache geolocation data for 24 hours using geoip2."""
        cache_key = f"geo_{ip}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return cached_data

        geo_data = {'country': None, 'city': None}

        if self.geo_reader:
            try:
                response = self.geo_reader.city(ip)
                geo_data['country'] = response.country.name
                geo_data['city'] = response.city.name
            except Exception:
                # Localhost or private IPs will fail
                pass

        # Cache for 24 hours (86400 seconds)
        cache.set(cache_key, geo_data, timeout=86400)
        return geo_data