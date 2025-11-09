from celery import shared_task
from django.utils import timezone
from django.db import models
from datetime import timedelta
from .models import RequestLog, SuspiciousIP

SENSITIVE_PATHS = ['/admin', '/login']

@shared_task
def detect_suspicious_ips():
    """Detect IPs with >100 requests/hour or accessing sensitive paths."""
    one_hour_ago = timezone.now() - timedelta(hours=1)

    # 1. Find IPs with >100 requests in the last hour
    frequent_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(request_count=models.Count('id'))
        .filter(request_count__gt=100)
    )

    for entry in frequent_ips:
        ip = entry['ip_address']
        reason = f"High request volume: {entry['request_count']} requests/hour"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)

    # 2. Find IPs accessing sensitive paths in the last hour
    sensitive_access_ips = (
        RequestLog.objects
        .filter(timestamp__gte=one_hour_ago, path__in=SENSITIVE_PATHS)
        .values('ip_address')
        .distinct()
    )

    for entry in sensitive_access_ips:
        ip = entry['ip_address']
        reason = "Accessed sensitive path"
        SuspiciousIP.objects.get_or_create(ip_address=ip, reason=reason)
