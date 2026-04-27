from rest_framework import serializers
from .models import Scan, Finding, ScanLog


class FindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = "__all__"


class ScanLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanLog
        fields = "__all__"


class ScanListSerializer(serializers.ModelSerializer):
    findings_count = serializers.IntegerField(source="findings.count", read_only=True)

    class Meta:
        model = Scan
        fields = [
            "id", "name", "target_url", "status",
            "total_tests", "vulnerabilities_found",
            "findings_count", "created_at", "updated_at",
        ]


class ScanDetailSerializer(serializers.ModelSerializer):
    findings = FindingSerializer(many=True, read_only=True)
    logs = ScanLogSerializer(many=True, read_only=True)

    class Meta:
        model = Scan
        fields = "__all__"


class ScanCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = [
            "name", "target_url",
            "user_a_credentials", "user_b_credentials",
            "admin_credentials", "endpoints", "config",
        ]

    def validate_endpoints(self, value):
        if not isinstance(value, list) or len(value) == 0:
            raise serializers.ValidationError("At least one endpoint is required.")
        for ep in value:
            if "path" not in ep:
                raise serializers.ValidationError("Each endpoint must have a 'path' field.")
            if "method" not in ep:
                ep["method"] = "GET"
            ep["method"] = ep["method"].upper()
        return value

    def validate_user_a_credentials(self, value):
        required = ["login_url", "username", "password"]
        for field in required:
            if field not in value:
                raise serializers.ValidationError(f"Missing required field: {field}")
        return value

    def validate_user_b_credentials(self, value):
        required = ["login_url", "username", "password"]
        for field in required:
            if field not in value:
                raise serializers.ValidationError(f"Missing required field: {field}")
        return value
