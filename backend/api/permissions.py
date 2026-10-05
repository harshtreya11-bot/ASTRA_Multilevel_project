from rest_framework import permissions


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Object-level permission to allow users to read/edit their own uploads or log entries,
    while allowing administrative staff full access.
    """

    def has_object_permission(self, request, view, obj):
        if request.user and request.user.is_staff:
            return True
        if hasattr(obj, 'user'):
            return obj.user == request.user
        return False


class IsAdminUserOrReadOnly(permissions.BasePermission):
    """
    Allows full access to staff/admin users, read-only to others.
    """

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return bool(request.user and request.user.is_authenticated)
        return bool(request.user and request.user.is_staff)


class IsAnalyst(permissions.BasePermission):
    """
    Allows access to authenticated analysts / users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)


class IsHQAdmin(permissions.BasePermission):
    """
    Allows access only to HQ Admin (staff or superuser) users.
    """

    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated and (request.user.is_staff or request.user.is_superuser))
