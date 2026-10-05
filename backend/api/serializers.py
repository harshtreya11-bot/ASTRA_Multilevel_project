import os
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.models import User
from .models import UploadedFile, LogEntry, AuditLog


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT serializer returning user profile info alongside access and refresh tokens.
    """
    def validate(self, attrs):
        data = super().validate(attrs)
        data['user'] = {
            'id': self.user.id,
            'username': self.user.username,
            'email': self.user.email,
            'is_staff': self.user.is_staff,
            'is_superuser': self.user.is_superuser,
        }
        return data


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_staff']


class FileUploadSerializer(serializers.Serializer):
    """
    Validates uploaded file format and size limits.
    Supports .csv, .log, and .txt files.
    """
    file = serializers.FileField(required=True)
    
    # Maximum allowed size: 50MB
    MAX_FILE_SIZE = 50 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'.csv': 'csv', '.log': 'log', '.txt': 'txt'}

    def validate_file(self, value):
        ext = os.path.splitext(value.name)[1].lower()
        if ext not in self.ALLOWED_EXTENSIONS:
            raise serializers.ValidationError(
                f"Unsupported file format '{ext}'. Allowed extensions are: .csv, .log, .txt"
            )
        if value.size > self.MAX_FILE_SIZE:
            size_mb = value.size / (1024 * 1024)
            raise serializers.ValidationError(
                f"File size ({size_mb:.2f} MB) exceeds maximum limit of 50 MB."
            )
        return value


class UploadedFileSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    user_email = serializers.CharField(source='user.email', read_only=True)

    class Meta:
        model = UploadedFile
        fields = [
            'id',
            'username',
            'user_email',
            'original_filename',
            'file_format',
            'file_size_bytes',
            'status',
            'total_records',
            'error_records',
            'error_message',
            'uploaded_at',
            'processed_at',
        ]
        read_only_fields = fields


class LogEntrySerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    filename = serializers.CharField(source='uploaded_file.original_filename', read_only=True)

    class Meta:
        model = LogEntry
        fields = [
            'id',
            'uploaded_file',
            'filename',
            'username',
            'timestamp',
            'raw_timestamp',
            'log_level',
            'source',
            'message',
            'raw_line',
            'extra_data',
            'line_number',
            'created_at',
        ]
        read_only_fields = fields


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True, default='System')

    class Meta:
        model = AuditLog
        fields = [
            'id',
            'username',
            'action',
            'details',
            'ip_address',
            'user_agent',
            'created_at',
        ]
        read_only_fields = fields
