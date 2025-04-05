from django.urls import path
from . import views

from rest_framework_simplejwt.views import (
    TokenRefreshView
)

app_name='users'
from .views import (
    PasswordResetOTPEmailView,
    PasswordResetConfirmationView
)

urlpatterns = [
    path("register/", views.RegisterView.as_view(), name="register"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutAPIView.as_view(), name="logout"),
    path("api/token/refresh", TokenRefreshView.as_view(), name="token_refresh"),
    
    path('auth/user/', views.UserProfileView.as_view(), name='user-profile'),
    path('auth/password/change/', views.PasswordChangeView.as_view(), name='password-change'),
    path('auth/password/reset/', views.PasswordResetOTPEmailView.as_view(), name='password-reset'),


    
    # urls.py
    path('api/verify-email/<str:uidb64>/<str:token>/', 
         views.VerifyEmail.as_view(), 
         name='verify-email'),
    
    path('api/resend-verification/', views.resend_verification, name="resend-verification"),
    
    path('api/token/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    
    # path('verify-email/<str:token>/', views.VerifyEmail.as_view(), name='verify-email'),
    
    # path("reset-password-email/", PasswordResetOTPEmailView.as_view(), name="reset_password_email"),
    # path("reset-password-confirmation/", PasswordResetConfirmationView.as_view(), name="reset_password_confirmation"),
    
    path('api/password-reset/', PasswordResetOTPEmailView.as_view(), name='password-reset'),
    path('api/password-reset/confirm/', PasswordResetConfirmationView.as_view()),
]
