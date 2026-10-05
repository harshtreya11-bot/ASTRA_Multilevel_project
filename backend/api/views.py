import csv
import io
import logging
import os
from collections import deque

from django.db import transaction
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import AuditLog, LogEntry, UploadedFile
from .pagination import StandardResultsSetPagination
from .parsers import LogParserEngine
from .permissions import IsAnalyst, IsHQAdmin
from .serializers import (
    AuditLogSerializer,
    CustomTokenObtainPairSerializer,
    FileUploadSerializer,
    LogEntrySerializer,
    UploadedFileSerializer,
)

logger = logging.getLogger(__name__)


class CustomLoginView(TokenObtainPairView):
    """View to authenticate users and issue JWT access and refresh token pairs."""

    serializer_class = CustomTokenObtainPairSerializer


class LogUploadView(APIView):
    """View handling bulk log file uploads (CSV, LOG, TXT) and audit log generation."""

    permission_classes = [IsAuthenticated, IsAnalyst]
    parser_classes = [MultiPartParser, FormParser]

    def _get_client_ip(self, request) -> str:
        """Extract client IP address accounting for reverse proxies."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '')

    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = serializer.validated_data['file']
        file_ext = os.path.splitext(uploaded_file.name)[1].lower()
        file_format = FileUploadSerializer.ALLOWED_EXTENSIONS.get(file_ext, 'csv')

        try:
            with transaction.atomic():
                file_record = UploadedFile.objects.create(
                    user=request.user,
                    file=uploaded_file,
                    original_filename=uploaded_file.name,
                    file_format=file_format,
                    file_size_bytes=uploaded_file.size,
                    status=UploadedFile.STATUS_PROCESSING,
                )

                parsed_entries = list(LogParserEngine.parse_file(uploaded_file, file_format))

                if not parsed_entries:
                    file_record.status = UploadedFile.STATUS_FAILED
                    file_record.error_message = "The uploaded file contains no parseable log records."
                    file_record.save()
                    return Response(
                        {"error": "The uploaded log file contains no parseable records."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                logs_to_create = [
                    LogEntry(
                        uploaded_file=file_record,
                        user=request.user,
                        timestamp=entry.get('timestamp'),
                        raw_timestamp=entry.get('raw_timestamp'),
                        log_level=entry.get('log_level', LogEntry.LEVEL_UNKNOWN),
                        source=entry.get('source', ''),
                        message=entry.get('message', ''),
                        raw_line=entry.get('raw_line', ''),
                        extra_data=entry.get('extra_data', {}),
                        line_number=entry.get('line_number', idx),
                    )
                    for idx, entry in enumerate(parsed_entries, start=1)
                ]

                LogEntry.objects.bulk_create(logs_to_create, batch_size=1000)

                file_record.status = UploadedFile.STATUS_COMPLETED
                file_record.total_records = len(logs_to_create)
                file_record.save()

                AuditLog.objects.create(
                    user=request.user,
                    action='log_upload',
                    details={
                        'filename': uploaded_file.name,
                        'file_format': file_format,
                        'record_count': len(logs_to_create),
                    },
                    ip_address=self._get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                )

            return Response(
                {
                    "message": "Logs uploaded and parsed successfully.",
                    "file_id": file_record.id,
                    "count": len(logs_to_create),
                    "file": UploadedFileSerializer(file_record).data,
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as exc:
            logger.error("Failed to process log upload: %s", exc, exc_info=True)
            return Response(
                {"error": "An error occurred while processing the log upload."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class MyDashboardView(APIView):
    """View retrieving log entries created by the currently authenticated analyst."""

    permission_classes = [IsAuthenticated, IsAnalyst]

    def get(self, request):
        logs = LogEntry.objects.filter(user=request.user).select_related('user', 'uploaded_file')
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(logs, request)
        if page is not None:
            serializer = LogEntrySerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        serializer = LogEntrySerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AllDashboardView(APIView):
    """View retrieving all system log entries across analysts for HQ Admins."""

    permission_classes = [IsAuthenticated, IsHQAdmin]

    def get(self, request):
        logs = LogEntry.objects.select_related('user', 'uploaded_file').all()
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(logs, request)
        if page is not None:
            serializer = LogEntrySerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        serializer = LogEntrySerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AuditLogView(APIView):
    """View retrieving compliance audit log records for HQ Admins."""

    permission_classes = [IsAuthenticated, IsHQAdmin]

    def get(self, request):
        logs = AuditLog.objects.select_related('user').all()
        paginator = StandardResultsSetPagination()
        page = paginator.paginate_queryset(logs, request)
        if page is not None:
            serializer = AuditLogSerializer(page, many=True)
            return paginator.get_paginated_response(serializer.data)

        serializer = AuditLogSerializer(logs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SystemLogReaderView(APIView):
    """View reading real-time system log files from disk for HQ Admins."""

    permission_classes = [IsAuthenticated, IsHQAdmin]

    def get(self, request):
        log_file_path = '/var/log/astra_app/system_events.log'

        if not os.path.exists(log_file_path):
            return Response(
                {
                    "message": "System log file not found on server. Showing dummy data for testing.",
                    "logs": [
                        "2026-10-01 10:00:00 INFO System started successfully",
                        "2026-10-01 10:05:00 WARNING High CPU usage detected on Node-1",
                        "2026-10-01 10:10:00 ERROR Failed login attempt from 192.168.1.50",
                    ],
                },
                status=status.HTTP_200_OK,
            )

        try:
            with open(log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                last_lines = deque(f, 100)

            raw_logs = [line.strip() for line in last_lines if line.strip()]

            return Response(
                {
                    "file": os.path.basename(log_file_path),
                    "lines_read": len(raw_logs),
                    "logs": raw_logs,
                },
                status=status.HTTP_200_OK,
            )

        except PermissionError:
            return Response(
                {"error": "Permission denied. Check server file permissions."},
                status=status.HTTP_403_FORBIDDEN,
            )
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)