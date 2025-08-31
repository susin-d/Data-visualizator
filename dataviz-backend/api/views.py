# dataviz-backend/api/views.py

# --- Django and Python Imports ---
from django.http import JsonResponse
from django.contrib.auth.models import User
import pandas as pd

# --- Django Rest Framework Imports ---
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework import status

# --- Local App Imports ---
from .models import UploadedFile, Profile
from .serializers import UploadedFileSerializer, UserProfileSerializer
from .permissions import IsAdmin, IsSuperAdmin
from django.db.models import Q # <-- Add this import for OR queries
# dataviz-backend/api/views.py

# ... (keep other imports)
from django.db.models import Q

class GetUserEmailView(APIView):
    """
    A public endpoint to resolve a username or email into a confirmed email.
    This is the first step of the username/email login flow.
    Handles both regular users (Firebase UID as username) and Django superusers.
    """
    permission_classes = [] # No authentication needed

    def post(self, request):
        identifier = request.data.get('identifier')
        if not identifier:
            return Response({'error': 'Identifier not provided.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Use Q object for a case-insensitive search in both username and email fields
            user = User.objects.get(
                Q(username__iexact=identifier) | Q(email__iexact=identifier)
            )
            
            # CRITICAL: We must ensure the user has an email.
            # A user created via Firebase always will, but a Django user might not.
            if not user.email:
                return Response({'error': 'User found, but no email is associated with this account. Cannot log in via Firebase.'}, status=status.HTTP_400_BAD_REQUEST)

            return Response({'email': user.email})

        except User.DoesNotExist:
            return Response({'error': f"No user found with the identifier '{identifier}'."}, status=status.HTTP_404_NOT_FOUND)
        except User.MultipleObjectsReturned:
            # This is an edge case where, for example, one user's username is another user's email.
            return Response({'error': 'Multiple accounts found with this identifier. Please use your email address to log in.'}, status=status.HTTP_400_BAD_REQUEST)


# ================================================================= #
#                         USER-FACING VIEWS                         #
# ================================================================= #

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        profile, created = Profile.objects.get_or_create(user=request.user)
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)

class MyStatsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        user = request.user
        total_uploads = UploadedFile.objects.filter(user=user).count()
        current_uploads = UploadedFile.objects.filter(user=user, is_deleted=False).count()
        deleted_uploads = total_uploads - current_uploads
        stats = {'totalUploads': total_uploads, 'currentUploads': current_uploads, 'deletedUploads': deleted_uploads}
        return Response(stats)

class MyRecentUploadsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        recent_files = UploadedFile.objects.filter(user=request.user, is_deleted=False).order_by('-upload_date')[:10]
        serializer = UploadedFileSerializer(recent_files, many=True)
        return Response(serializer.data)

class MyAllFilesView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        all_files = UploadedFile.objects.filter(user=request.user).order_by('-upload_date')
        serializer = UploadedFileSerializer(all_files, many=True)
        return Response(serializer.data)

class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    def post(self, request, *args, **kwargs):
        file_obj = request.data.get('file')
        if not file_obj:
            return Response({'error': 'No file provided.'}, status=status.HTTP_400_BAD_REQUEST)
        UploadedFile.objects.create(user=request.user, file=file_obj, filename=file_obj.name, filesize=file_obj.size)
        return Response({'message': 'File uploaded successfully'}, status=status.HTTP_201_CREATED)

class FileDeleteView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request, pk):
        try:
            file_to_delete = UploadedFile.objects.get(pk=pk, user=request.user)
            file_to_delete.is_deleted = True
            file_to_delete.save()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except UploadedFile.DoesNotExist:
            return Response({'error': 'File not found or you do not have permission.'}, status=status.HTTP_404_NOT_FOUND)

class VisualizeFileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        try:
            uploaded_file = UploadedFile.objects.get(pk=pk, user=request.user, is_deleted=False)
            file_path = uploaded_file.file.path
            MAX_ROWS_FOR_VIZ = 5000 
            if file_path.endswith('.csv'):
                df = pd.read_csv(file_path, nrows=MAX_ROWS_FOR_VIZ)
            elif file_path.endswith(('.xls', '.xlsx')):
                df_full = pd.read_excel(file_path)
                df = df_full.sample(n=MAX_ROWS_FOR_VIZ) if len(df_full) > MAX_ROWS_FOR_VIZ else df_full
            else:
                return Response({'error': 'Unsupported file type.'}, status=status.HTTP_400_BAD_REQUEST)
            chart_data = df.to_json(orient='records')
            return JsonResponse(chart_data, safe=False)
        except UploadedFile.DoesNotExist:
            return Response({'error': 'File not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Could not process file. Error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ProcessFileForChartsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        try:
            uploaded_file = UploadedFile.objects.get(pk=pk, user=request.user, is_deleted=False)
            file_path = uploaded_file.file.path
            x_axis = request.query_params.get('x_axis')
            y_axis = request.query_params.get('y_axis')
            if not x_axis or not y_axis: return Response({'error': 'x_axis and y_axis query parameters are required.'}, status=status.HTTP_400_BAD_REQUEST)
            
            if file_path.endswith('.csv'): df = pd.read_csv(file_path)
            elif file_path.endswith(('.xls', '.xlsx')): df = pd.read_excel(file_path)
            else: return Response({'error': 'Unsupported file type.'}, status=status.HTTP_400_BAD_REQUEST)

            if x_axis not in df.columns or y_axis not in df.columns: return Response({'error': 'Selected columns not found in the file.'}, status=status.HTTP_400_BAD_REQUEST)
            
            bar_line_data, pie_chart_data = [], []
            if pd.api.types.is_numeric_dtype(df[y_axis]):
                grouped_data = df.groupby(x_axis)[y_axis].sum().reset_index()
                bar_line_data = grouped_data.nlargest(25, y_axis).to_dict('records')
                MAX_PIE_SLICES = 9
                pie_data_sorted = grouped_data.nlargest(len(grouped_data), y_axis)
                if len(pie_data_sorted) > MAX_PIE_SLICES:
                    top_data = pie_data_sorted.head(MAX_PIE_SLICES)
                    others_sum = pie_data_sorted.tail(len(pie_data_sorted) - MAX_PIE_SLICES)[y_axis].sum()
                    others_row = pd.DataFrame([{x_axis: 'Others', y_axis: others_sum}])
                    pie_chart_data = pd.concat([top_data, others_row]).to_dict('records')
                else: pie_chart_data = pie_data_sorted.to_dict('records')
            else:
                value_counts = df[x_axis].value_counts().reset_index()
                value_counts.columns = [x_axis, 'count']
                bar_line_data = value_counts.nlargest(25, 'count').to_dict('records')

            response_data = {'bar_line_data': bar_line_data, 'pie_chart_data': pie_chart_data}
            return Response(response_data)
        except UploadedFile.DoesNotExist: return Response({'error': 'File not found.'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e: return Response({'error': f'Could not process file. Error: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteUserAccountView(APIView):
    permission_classes = [IsAuthenticated]
    def delete(self, request):
        user = request.user
        try:
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Exception as e:
            return Response({"error": f"An error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ================================================================= #
#                          ADMIN-ONLY VIEWS                         #
# ================================================================= #
class AdminStatsView(APIView):
    permission_classes = [IsAdmin]
    def get(self, request):
        total_uploads = UploadedFile.objects.count()
        current_uploads = UploadedFile.objects.filter(is_deleted=False).count()
        deleted_uploads = total_uploads - current_uploads
        return Response({'totalUploads': total_uploads, 'currentUploads': current_uploads, 'deletedUploads': deleted_uploads})

class AdminRecentUploadsView(APIView):
    permission_classes = [IsAdmin]
    def get(self, request):
        recent_files = UploadedFile.objects.filter(is_deleted=False).order_by('-upload_date')[:5]
        serializer = UploadedFileSerializer(recent_files, many=True)
        return Response(serializer.data)

# ================================================================= #
#                       SUPER ADMIN-ONLY VIEWS                      #
# ================================================================= #
class UserListView(APIView):
    permission_classes = [IsSuperAdmin]
    def get(self, request):
        profiles = Profile.objects.select_related('user').exclude(user=request.user)
        serializer = UserProfileSerializer(profiles, many=True)
        return Response(serializer.data)

class PromoteUserView(APIView):
    permission_classes = [IsSuperAdmin]
    def post(self, request, pk):
        try:
            profile_to_update = Profile.objects.get(user__pk=pk)
            if profile_to_update.role == Profile.Role.USER:
                profile_to_update.role = Profile.Role.ADMIN
                message = f'User {profile_to_update.user.email} promoted to Admin.'
            elif profile_to_update.role == Profile.Role.ADMIN:
                profile_to_update.role = Profile.Role.USER
                message = f'User {profile_to_update.user.email} demoted to User.'
            else:
                return Response({'error': 'Cannot change the role of a Super Admin.'}, status=status.HTTP_400_BAD_REQUEST)
            profile_to_update.save()
            return Response({'message': message})
        except Profile.DoesNotExist:
            return Response({'error': 'User profile not found.'}, status=status.HTTP_404_NOT_FOUND)
# dataviz-backend/api/views.py

# --- Django and Python Imports ---
import random
from django.core.mail import send_mail
from django.conf import settings
from firebase_admin import auth
import random # <--- Add this import
from django.core.mail import send_mail # <--- Add this import
from django.conf import settings # <--- Add this import

# --- Local App Imports ---
from .models import UploadedFile, Profile, OTP
# ... (keep other imports)


# ================================================================= #
#                     AUTHENTICATION VIEWS                          #
# ================================================================= #

class RequestPasswordResetView(APIView):
    """
    Handles a request to send a password reset OTP to a user's email.
    No authentication required.
    """
    permission_classes = [] 

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email__iexact=email) # Case-insensitive email lookup
        except User.DoesNotExist:
            # Important: Do not reveal if an email exists for security reasons.
            # Send a success message anyway.
            return Response({'message': 'If an account with this email exists, an OTP has been sent.'})

        # Invalidate any old OTPs for this user
        OTP.objects.filter(user=user).delete()
        
        # Create a new 6-digit OTP
        otp_code = str(random.randint(100000, 999999))
        OTP.objects.create(user=user, code=otp_code)

        # Send the email
        subject = 'Your Password Reset OTP for DataViz Pro'
        message = f'Your One-Time Password is: {otp_code}\nThis code is valid for 5 minutes.'
        
        try:
            send_mail(subject, message, settings.EMAIL_HOST_USER, [email])
        except Exception as e:
            # Log the error, but don't expose details to the user
            print(f"ERROR: Could not send password reset email to {email}. Reason: {e}")
            return Response({'error': 'Could not send email. Please try again later.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'If an account with this email exists, an OTP has been sent.'})


class ResetPasswordView(APIView):
    """
    Verifies an OTP and resets the user's password.
    No authentication required.
    """
    permission_classes = []

    def post(self, request):
        email = request.data.get('email')
        otp_code = request.data.get('otp')
        new_password = request.data.get('password')

        if not all([email, otp_code, new_password]):
             return Response({'error': 'Email, OTP, and new password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(email__iexact=email)
            otp_instance = OTP.objects.get(user=user, code=otp_code)
        except (User.DoesNotExist, OTP.DoesNotExist):
            return Response({'error': 'Invalid OTP or email. Please try again.'}, status=status.HTTP_400_BAD_REQUEST)

        if otp_instance.is_expired():
            otp_instance.delete()
            return Response({'error': 'Your OTP has expired. Please request a new one.'}, status=status.HTTP_400_BAD_REQUEST)

        # Reset password in Django
        user.set_password(new_password)
        user.save()
        
        # Attempt to reset password in Firebase
        try:
            auth.update_user(user.username, password=new_password)
        except Exception as e:
            print(f"Warning: Could not update password in Firebase for user {user.username}: {e}")

        otp_instance.delete() # OTP is now used and should be deleted
        return Response({'message': 'Password has been reset successfully.'})


# ================================================================= #
#                         USER-FACING VIEWS                         #
# ================================================================= #

class UserDetailView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        profile, created = Profile.objects.get_or_create(user=request.user)
        serializer = UserProfileSerializer(profile)
        return Response(serializer.data)
