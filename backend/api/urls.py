from django.urls import path
from .views import (
    CustomLoginView, LogUploadView, MyDashboardView,
    AllDashboardView, AuditLogView, SystemLogReaderView # Naya import
)

urlpatterns = [
    path('auth/login/', CustomLoginView.as_view(), name='token_obtain_pair'),
    path('logs/upload/', LogUploadView.as_view(), name='log_upload'),
    path('dashboard/my-data/', MyDashboardView.as_view(), name='my_dashboard'),
    path('dashboard/all-data/', AllDashboardView.as_view(), name='all_dashboard'),
    path('audit-log/', AuditLogView.as_view(), name='audit_log'),
    
    # Naya Endpoint for System Logs
    path('logs/system-reader/', SystemLogReaderView.as_view(), name='system_log_reader'),
]