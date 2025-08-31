# dataviz-backend/api/authentication.py

import firebase_admin
from firebase_admin import credentials, auth
from django.conf import settings
from django.contrib.auth.models import User
from rest_framework import authentication, exceptions
import os

# --- Lazy Firebase Initialization (This part is already correct) ---
def initialize_firebase_once():
    if not firebase_admin._apps:
        try:
            service_account_key_path = settings.GOOGLE_APPLICATION_CREDENTIALS
            if not service_account_key_path:
                raise ValueError("GOOGLE_APPLICATION_CREDENTIALS environment variable not set.")
            absolute_path = os.path.join(settings.BASE_DIR, service_account_key_path)
            cred = credentials.Certificate(absolute_path)
            firebase_admin.initialize_app(cred)
            print("Firebase Admin SDK initialized successfully.")
        except Exception as e:
            print(f"CRITICAL: Failed to initialize Firebase Admin SDK: {e}")
            raise e

# --- Custom Firebase Authentication Class (The Fix) ---
class FirebaseAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        initialize_firebase_once()
        
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None # No token provided or malformed header

        try:
            id_token = auth_header.split(' ').pop()
            decoded_token = auth.verify_id_token(id_token)
        except Exception as e:
            # If token verification fails for any reason, deny authentication.
            raise exceptions.AuthenticationFailed(f'Invalid or expired Firebase token: {e}')

        if not decoded_token or 'uid' not in decoded_token:
            raise exceptions.AuthenticationFailed('Invalid token payload.')

        # --- THIS IS THE ROBUST PART ---
        # Try to get the user. If they don't exist, create them.
        # This is a single, atomic database operation.
        try:
            user, created = User.objects.get_or_create(
                username=decoded_token.get('uid'),
                defaults={
                    'email': decoded_token.get('email', '')
                }
            )
            # The post_save signal in models.py will automatically create the
            # user's profile if `created` is True.
            
            return (user, None)  # Authentication successful

        except Exception as e:
            # This would catch a potential database error during user creation.
            raise exceptions.APIException(f'Error creating or retrieving Django user: {e}')
