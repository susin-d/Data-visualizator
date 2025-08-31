# dataviz-backend/dataviz_project/urls.py

from django.contrib import admin
from django.urls import path, include  # <-- Make sure 'include' is imported
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    
    # This is the ONLY path you need here for your app.
    # It tells Django to hand off any URL starting with 'api/' to your api app's urls.py
    path('api/', include('api.urls')),
    
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)