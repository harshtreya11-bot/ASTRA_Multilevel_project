from django.db import models
from django.contrib.auth.models import User


class UploadedFile(models.Model):
    """
    Stores metadata for uploaded log files (CSV, LOG, TXT).
    """
    FORMAT_CSV = 'csv'
    FORMAT_LOG = 'log'
    FORMAT_TXT = 'txt'
    
    FORMAT_CHOICES = [
        (FORMAT_CSV, 'CSV File'),
        (FORMAT_LOG, 'Log File'),
        (FORMAT_TXT, 'Text File'),
    ]

    STATUS_PENDING = 'PENDING'
    STATUS_PROCESSING = 'PROCESSING'
    STATUS_COMPLETED = 'COMPLETED'
    STATUS_FAILED = 'FAILED'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_PROCESSING, 'Processing'),
        (STATUS_COMPLETED, 'Completed'),
        (STATUS_FAILED, 'Failed'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_files')
    file = models.FileField(upload_to='logs/%Y/%m/%d/')
    original_filename = models.CharField(max_length=255)
    file_format = models.CharField(max_length=10, choices=FORMAT_CHOICES)
    file_size_bytes = models.BigIntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    total_records = models.IntegerField(default=0)
    error_records = models.IntegerField(default=0)
    error_message = models.TextField(blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-uploaded_at']

    def __str__(self):
        return f"{self.original_filename} ({self.file_format.upper()}) - {self.user.username}"


class LogEntry(models.Model):
    """
    Stores normalized parsed log record entries from CSV, LOG, or TXT files.
    """
    LEVEL_DEBUG = 'DEBUG'
    LEVEL_INFO = 'INFO'
    LEVEL_WARNING = 'WARNING'
    LEVEL_ERROR = 'ERROR'
    LEVEL_CRITICAL = 'CRITICAL'
    LEVEL_UNKNOWN = 'UNKNOWN'

    LEVEL_CHOICES = [
        (LEVEL_DEBUG, 'Debug'),
        (LEVEL_INFO, 'Info'),
        (LEVEL_WARNING, 'Warning'),
        (LEVEL_ERROR, 'Error'),
        (LEVEL_CRITICAL, 'Critical'),
        (LEVEL_UNKNOWN, 'Unknown'),
    ]

    uploaded_file = models.ForeignKey(UploadedFile, on_delete=models.CASCADE, related_name='entries')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='log_entries')
    timestamp = models.DateTimeField(null=True, blank=True, db_index=True)
    raw_timestamp = models.CharField(max_length=100, blank=True, null=True)
    log_level = models.CharField(max_length=20, choices=LEVEL_CHOICES, default=LEVEL_UNKNOWN, db_index=True)
    source = models.CharField(max_length=255, blank=True, null=True, db_index=True)
    message = models.TextField()
    raw_line = models.TextField(blank=True, null=True)
    extra_data = models.JSONField(default=dict, blank=True)
    line_number = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp', '-id']
        indexes = [
            models.Index(fields=['user', 'log_level']),
            models.Index(fields=['uploaded_file', 'log_level']),
        ]

    def __str__(self):
        return f"[{self.log_level}] {self.source or 'system'} - {self.message[:50]}"


class AuditLog(models.Model):
    """
    Tracks system activities, file uploads, login events, and administrative views.
    """
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='audit_logs')
    action = models.CharField(max_length=100, db_index=True)
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        user_str = self.user.username if self.user else 'System'
        return f"{self.created_at} - {user_str} - {self.action}"

