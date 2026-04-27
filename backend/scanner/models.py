import uuid
from django.db import models


class Scan(models.Model):
    """A single IDOR scan session."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255)
    target_url = models.URLField(help_text="Base URL of the target application")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)

    # Authentication for two users (horizontal IDOR)
    user_a_credentials = models.JSONField(
        help_text="Credentials for User A: {login_url, username_field, password_field, username, password, extra_fields}",
    )
    user_b_credentials = models.JSONField(
        help_text="Credentials for User B (same format as User A)",
    )

    # Optional: admin credentials for vertical privilege escalation testing
    admin_credentials = models.JSONField(
        blank=True,
        null=True,
        help_text="Optional admin credentials for vertical IDOR testing",
    )

    # Endpoints to test
    endpoints = models.JSONField(
        help_text="List of endpoint configs: [{path, method, id_param, id_location, sample_id}]",
    )

    # Configuration
    config = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional config: {test_methods, check_encoded_ids, check_uuid, check_sequential, custom_headers}",
    )

    # Results summary
    total_tests = models.IntegerField(default=0)
    vulnerabilities_found = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} - {self.target_url}"


class Finding(models.Model):
    """An individual IDOR vulnerability finding."""

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Informational"

    class IDORType(models.TextChoices):
        HORIZONTAL = "horizontal", "Horizontal Privilege Escalation"
        VERTICAL = "vertical", "Vertical Privilege Escalation"
        DATA_LEAK = "data_leak", "Data Leak"
        UNAUTHORIZED_MODIFY = "unauthorized_modify", "Unauthorized Modification"
        UNAUTHORIZED_DELETE = "unauthorized_delete", "Unauthorized Deletion"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="findings")

    endpoint = models.CharField(max_length=500)
    method = models.CharField(max_length=10)
    severity = models.CharField(max_length=20, choices=Severity.choices)
    idor_type = models.CharField(max_length=30, choices=IDORType.choices)

    description = models.TextField()
    evidence = models.JSONField(
        help_text="Request/response evidence: {request, response, expected_status, actual_status}",
    )
    remediation = models.TextField(blank=True)

    # What was tested
    original_id = models.CharField(max_length=500, help_text="The original resource ID")
    tested_id = models.CharField(max_length=500, help_text="The ID used in the attack")
    id_location = models.CharField(
        max_length=50,
        help_text="Where the ID was found: path, query, body, header",
    )

    is_vulnerable = models.BooleanField(default=False)
    ai_analysis = models.TextField(blank=True, help_text="LLM analysis of the finding")

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"[{self.severity}] {self.endpoint} - {self.idor_type}"


class ScanLog(models.Model):
    """Real-time log entries for a scan."""

    class Level(models.TextChoices):
        DEBUG = "debug", "Debug"
        INFO = "info", "Info"
        WARNING = "warning", "Warning"
        ERROR = "error", "Error"
        SUCCESS = "success", "Success"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="logs")
    level = models.CharField(max_length=10, choices=Level.choices, default=Level.INFO)
    message = models.TextField()
    details = models.JSONField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at"]

    def __str__(self):
        return f"[{self.level}] {self.message[:80]}"
