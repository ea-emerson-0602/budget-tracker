from datetime import timedelta, timezone
from django.db import models
from django.contrib.auth.models import AbstractUser

from rest_framework_simplejwt.tokens import RefreshToken
# Create your models here.

class CustomUser(AbstractUser):
    # pass
    username = models.CharField(max_length=100, null=True, blank=True, unique=True)
    email = models.EmailField(max_length=100, unique=True, db_index=True)
    full_name = models.CharField(max_length=100, blank=True, null=True)
    GENDER_CHOICES = [('M', 'Male'),
                      ('F', 'Female'),
                      ('O', 'Other')]
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True, null=True)
    is_authorized = models.BooleanField(default=False)
    
    def __str__(self) -> str:
        return self.username
    
    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }
    login_token = models.CharField(max_length=6, null=True, blank=True)
    token_created_at = models.DateTimeField(null=True, blank=True)

    def is_otp_valid(self):
        return self.token_created_at and \
               timezone.now() < self.token_created_at + timedelta(minutes=15)
               
    profile_picture = models.ImageField(
        upload_to='profile_pics/',
        null=True,
        blank=True,
        default='profile_pics/default.png'
    )
    
    # Add this method for profile picture URL
    @property
    def profile_picture_url(self):
        if self.profile_picture:
            return self.profile_picture.url
        return '/static/profile_pics/default.png'

    # Add fields like profile picture later if necessary