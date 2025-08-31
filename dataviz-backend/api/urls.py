from django.urls import path
from .views import (
    # --- User-facing views ---
    UserDetailView,
    MyStatsView,
    MyRecentUploadsView,
    MyAllFilesView,
    FileUploadView,
    FileDeleteView,
    VisualizeFileView,
    ProcessFileForChartsView,
    DeleteUserAccountView,

    # --- Authentication and Password Reset Views ---
    GetUserEmailView,
    RequestPasswordResetView,
    ResetPasswordView,

    # --- Admin-only views ---
    AdminStatsView,
    AdminRecentUploadsView,

    # --- Super Admin-only views ---
    UserListView,
    PromoteUserView,
)

urlpatterns = [
    # ======================================================= #
    #                Authentication & User                    #
    # ======================================================= #
    # Public endpoint to resolve username/email for login
    path('auth/get-email/', GetUserEmailView.as_view(), name='get-user-email'),
    # Public endpoints for password reset flow
    path('auth/request-password-reset/', RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('auth/reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    
    # Authenticated endpoints for user details and actions
    path('users/me/', UserDetailView.as_view(), name='user-detail'),
    path('users/me/stats/', MyStatsView.as_view(), name='my-stats'),
    path('users/me/delete/', DeleteUserAccountView.as_view(), name='user-delete'),


    # ======================================================= #
    #              File Management & Visualization            #
    # ======================================================= #
    path('files/my-recent/', MyRecentUploadsView.as_view(), name='my-recent-files'),
    path('files/my-all/', MyAllFilesView.as_view(), name='my-all-files'),
    path('files/upload/', FileUploadView.as_view(), name='file-upload'),
    path('files/<int:pk>/delete/', FileDeleteView.as_view(), name='file-delete'),
    
    # Legacy visualization endpoint (sends raw data, useful for getting column headers)
    path('files/<int:pk>/visualize/', VisualizeFileView.as_view(), name='file-visualize'),
    
    # New high-performance endpoint (sends aggregated data for fast charts)
    path('files/<int:pk>/process-for-charts/', ProcessFileForChartsView.as_view(), name='process-file-for-charts'),


    # ======================================================= #
    #                        Admin Endpoints                    #
    # ======================================================= #
    path('admin/stats/', AdminStatsView.as_view(), name='admin-stats'),
    path('admin/recent-uploads/', AdminRecentUploadsView.as_view(), name='admin-recent-uploads'),


    # ======================================================= #
    #                     Super Admin Endpoints                 #
    # ======================================================= #
    path('superadmin/users/', UserListView.as_view(), name='user-list'),
    path('superadmin/users/<int:pk>/promote/', PromoteUserView.as_view(), name='promote-user'),
]