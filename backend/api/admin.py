from django.contrib import admin
from .models import UploadedFile, LogEntry, AuditLog


@admin.register(UploadedFile)
class UploadedFileAdmin(admin.ModelAdmin):
    list_display = ('original_filename', 'user', 'file_format', 'status', 'total_records', 'uploaded_at')
    list_filter = ('file_format', 'status', 'uploaded_at')
    search_fields = ('original_filename', 'user__username', 'user__email')
    ordering = ('-uploaded_at',)


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ('id', 'log_level', 'source', 'user', 'timestamp', 'uploaded_file', 'line_number')
    list_filter = ('log_level', 'timestamp', 'created_at')
    search_fields = ('message', 'source', 'user__username', 'raw_line')
    ordering = ('-timestamp', '-id')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'user', 'action', 'ip_address', 'created_at')
    list_filter = ('action', 'created_at')
    search_fields = ('action', 'user__username', 'ip_address')
    ordering = ('-created_at',)
