import os
import threading
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.shortcuts import get_object_or_404

from .models import Scan, Finding, ScanLog
from .serializers import (
    ScanListSerializer,
    ScanDetailSerializer,
    ScanCreateSerializer,
    FindingSerializer,
    ScanLogSerializer,
)


def _run_scan_in_thread(scan_id):
    """Run the IDOR agent in a background thread.

    The agent spins up its own event loop and uses sync Django ORM inside
    coroutines. That trips Django's async_unsafe guard, so we opt into the
    documented escape hatch for this thread. It's safe here: each scan gets
    its own thread + loop, ORM calls are serial, and no async DB driver is
    in use.
    """
    os.environ.setdefault("DJANGO_ALLOW_ASYNC_UNSAFE", "true")

    import django
    django.setup()
    from .agent.idor_agent import IDORAgent

    agent = IDORAgent(scan_id)
    agent.run()


class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()

    def get_serializer_class(self):
        if self.action == "list":
            return ScanListSerializer
        if self.action == "create":
            return ScanCreateSerializer
        return ScanDetailSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        scan = serializer.save()
        return Response(
            ScanDetailSerializer(scan).data,
            status=status.HTTP_201_CREATED,
        )

    @action(detail=True, methods=["post"])
    def start(self, request, pk=None):
        scan = self.get_object()
        if scan.status == Scan.Status.RUNNING:
            return Response(
                {"error": "Scan is already running."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        scan.status = Scan.Status.RUNNING
        scan.save()

        thread = threading.Thread(target=_run_scan_in_thread, args=(str(scan.id),))
        thread.daemon = True
        thread.start()

        return Response({"status": "started", "scan_id": str(scan.id)})

    @action(detail=True, methods=["post"])
    def cancel(self, request, pk=None):
        scan = self.get_object()
        if scan.status != Scan.Status.RUNNING:
            return Response(
                {"error": "Scan is not running."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        scan.status = Scan.Status.CANCELLED
        scan.save()
        return Response({"status": "cancelled"})

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        scan = self.get_object()
        findings = scan.findings.all()
        severity = request.query_params.get("severity")
        if severity:
            findings = findings.filter(severity=severity)
        return Response(FindingSerializer(findings, many=True).data)

    @action(detail=True, methods=["get"])
    def logs(self, request, pk=None):
        scan = self.get_object()
        after = request.query_params.get("after")
        logs = scan.logs.all()
        if after:
            logs = logs.filter(created_at__gt=after)
        return Response(ScanLogSerializer(logs, many=True).data)


class FindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Finding.objects.all()
    serializer_class = FindingSerializer

    def get_queryset(self):
        qs = super().get_queryset()
        scan_id = self.request.query_params.get("scan")
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        return qs
