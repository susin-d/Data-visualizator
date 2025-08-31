# dataviz-backend/api/permissions.py

from rest_framework.permissions import BasePermission
from .models import Profile # Import the Profile model to check roles

class IsAdmin(BasePermission):
    """
    Custom permission to only allow users with ADMIN or SUPERADMIN role.
    """
    def has_permission(self, request, view):
        # Check if the user is authenticated and has a profile with the correct role
        return (
            request.user and
            request.user.is_authenticated and
            hasattr(request.user, 'profile') and
            (request.user.profile.role == Profile.Role.ADMIN or request.user.profile.role == Profile.Role.SUPERADMIN)
        )

class IsSuperAdmin(BasePermission):
    """
    Custom permission to only allow users with SUPERADMIN role.
    """
    def has_permission(self, request, view):
        # Check if the user is authenticated and has a profile with the SUPERADMIN role
        return (
            request.user and
            request.user.is_authenticated and
            hasattr(request.user, 'profile') and
            request.user.profile.role == Profile.Role.SUPERADMIN
        )