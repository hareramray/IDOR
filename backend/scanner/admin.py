from django.contrib import admin
from .models import Scan, Finding, ScanLog


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ["name", "target_url", "status", "vulnerabilities_found", "created_at"]
    list_filter = ["status"]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ["endpoint", "method", "severity", "idor_type", "is_vulnerable"]
    list_filter = ["severity", "idor_type", "is_vulnerable"]


@admin.register(ScanLog)
class ScanLogAdmin(admin.ModelAdmin):
    list_display = ["scan", "level", "message", "created_at"]
    list_filter = ["level"]
