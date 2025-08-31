# dataviz-backend/api/serializers.py
from rest_framework import serializers
from .models import UploadedFile, Profile
from django.contrib.auth.models import User

# --- Add this new serializer ---
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email']

class UserProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    class Meta:
        model = Profile
        fields = ['user', 'role']

# --- This is your existing serializer ---
class UploadedFileSerializer(serializers.ModelSerializer):
    upload_date = serializers.DateTimeField(format="%d %b %Y")
    class Meta:
        model = UploadedFile
        fields = ['id', 'filename', 'filesize', 'upload_date']