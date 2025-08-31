from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
# ================================================================= #
#                             Profile Model                         #
# ================================================================= #
class Profile(models.Model):
    """
    Extends Django's built-in User model to include a role for authorization.
    A Profile is linked one-to-one with a User.
    """
    class Role(models.TextChoices):
        USER = 'USER', 'User'
        ADMIN = 'ADMIN', 'Admin'
        SUPERADMIN = 'SUPERADMIN', 'Super Admin'

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=50, choices=Role.choices, default=Role.USER)

    def __str__(self):
        return f"{self.user.username}'s Profile - Role: {self.get_role_display()}"


# ================================================================= #
#                           UploadedFile Model                      #
# ================================================================= #
class UploadedFile(models.Model):
    """
    Stores metadata for each file uploaded by a user.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_files')
    file = models.FileField(upload_to='uploads/')
    filename = models.CharField(max_length=255)
    filesize = models.PositiveIntegerField() # Stored in bytes
    upload_date = models.DateTimeField(auto_now_add=True)
    is_deleted = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.filename} uploaded by {self.user.username}"


# ================================================================= #
#                               OTP Model                           #
# ================================================================= #
class OTP(models.Model):
    """
    Stores One-Time Passwords for the password reset functionality.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        """Checks if the OTP is older than 5 minutes."""
        return timezone.now() > self.created_at + timedelta(minutes=5)

    def __str__(self):
        return f"OTP for {self.user.username}"


# ================================================================= #
#                             Django Signals                        #
# ================================================================= #
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """
    This signal is triggered every time a User object is saved.
    If the user was just created, it automatically creates a
    corresponding Profile object with the default 'USER' role.
    """
    if created:
        Profile.objects.create(user=instance)