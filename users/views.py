from django.contrib.auth import get_user_model
from django.conf import settings
from backend.settings import DEFAULT_FROM_EMAIL
from django.core.mail import EmailMessage, BadHeaderError
from smtplib import SMTPException
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny
from django.core.mail import send_mail
from rest_framework.views import APIView
from .serializers import *
from django.contrib import messages
from django.shortcuts import redirect
from django.views.generic import DetailView
from django.http import Http404

from rest_framework.decorators import api_view
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import serializers, permissions
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class RegisterView(generics.GenericAPIView):
    serializer_class = RegisterSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # Generate verification token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        
        verification_link = f"{settings.FRONTEND_URL}/confirm-email/{uid}/{token}/"

        try:
            send_mail(
                'Confirm Your Email',
                f'Click here to verify your email: {verification_link}',
                str(DEFAULT_FROM_EMAIL),  # Use settings directly
                [user.email],
                fail_silently=False,
            )
        except (BadHeaderError, SMTPException) as e:
            # Log the error for debugging
            print(f"Email failed to send: {str(e)}")
            return Response(
                {'error': 'Failed to send verification email'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
        return Response({'message': 'Verification email sent!'}, status=status.HTTP_201_CREATED)
# users/views.py
from django.contrib.auth.tokens import PasswordResetTokenGenerator

User = get_user_model()
token_generator = PasswordResetTokenGenerator()

class VerifyEmail(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        try:
            # Decode user ID
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
            
            # Verify token
            if not token_generator.check_token(user, token):
                raise ValueError('Invalid token')
            
            # Activate user
            if not user.is_authorized:
                user.is_authorized = True
                user.save()
            
            return Response({'message': 'Email successfully verified!'}, 
                           status=status.HTTP_200_OK)
            
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({'error': 'Invalid or expired token'},
                          status=status.HTTP_400_BAD_REQUEST)        

@api_view(['POST'])
def resend_verification(request):
    try:
        email = request.data.get('email')
        if not email:
            return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.get(email=email)
        
        if user.is_authorized:
            return Response({'error': 'Email already verified'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate new verification token
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)
        verification_link = f"{settings.FRONTEND_URL}/confirm-email/{uid}/{token}/"

        # Send email
        send_mail(
            'Confirm Your Email',
            f'New verification link: {verification_link}',
            DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        
        return Response({'message': 'Verification email resent successfully'}, status=status.HTTP_200_OK)

    except User.DoesNotExist:
        return Response({'error': 'User with this email does not exist'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = CustomUser.objects.get(username=serializer.validated_data['username'])
        
        if user.is_authorized:
            response_data = serializer.validated_data
            response_data["detail"]= "Logged in successfully."
            
            # Generate a refresh token and set it for the user
            refresh = RefreshToken.for_user(user)
            user.refresh_token = str(refresh)
            user.save()
            
            response = Response(response_data, status=status.HTTP_200_OK)
            
            response.set_cookie('refreshToken', user.refresh_token, secure=True, samesite=None)
            
            return response
        return Response({"detail":"Your account has not been approved by an admin."}, status=status.HTTP_401_UNAUTHORIZED)
        
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        user = self.user
        
        if not user.is_authorized:
            raise serializers.ValidationError(
                "Account not verified. Please check your email for verification instructions."
            )
            
        return data

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class LogoutAPIView(generics.GenericAPIView):
    authentication_classes = []
    serializer_class = LogoutSerializer
    @permission_classes([AllowAny])
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'detail':'Successfully logged out'}, status=status.HTTP_200_OK)
        
       # views.py
class PasswordResetOTPEmailView(generics.CreateAPIView):
    serializer_class = PasswordResetSerializer
        
    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        user = User.objects.get(email=email)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.save()
        
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        
        verification_link = f"{settings.FRONTEND_URL}/reset-password/confirm/{uid}/{token}/"
       
        
        # Send email with OTP and generic link
        send_mail(
            'Password Reset OTP',
            f"Your OTP: {data['otp']}\n\nClick here to reset: {verification_link}",
            DEFAULT_FROM_EMAIL,
            [serializer.validated_data['email']],
            fail_silently=False,
        )
        
        return Response({'message': 'OTP sent to your email'}, status=status.HTTP_200_OK)

# views.py
# views.py
class PasswordResetConfirmationView(APIView):
    def post(self, request):
        try:
            serializer = PasswordResetConfirmSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            return Response({'message': 'Password updated successfully'}, status=200)
        
        except serializers.ValidationError as e:
            return Response(e.detail, status=400)
        
# users/views.py
class UserProfileView(generics.RetrieveUpdateAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def perform_update(self, serializer):
        # Handle profile picture upload
        if 'profile_picture' in self.request.FILES:
            serializer.save(profile_picture=self.request.FILES['profile_picture'])
        else:
            serializer.save()

# users/views.py
class PasswordChangeView(generics.CreateAPIView):
    serializer_class = PasswordChangeSerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        new_password = serializer.validated_data['new_password']

        # Verify OTP against logged-in user
        if not user.login_token == serializer.validated_data['otp']:
            return Response({"error": "Invalid OTP"}, status=status.HTTP_400_BAD_REQUEST)
            
        if not user.is_otp_valid():
            return Response({"error": "OTP has expired"}, status=status.HTTP_400_BAD_REQUEST)

        # Check if new password matches current password
        if user.check_password(new_password):
            return Response(
                {"error": "New password cannot be the same as old password"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Validate password complexity
        try:
            password_validation.validate_password(new_password, user)
        except password_validation.ValidationError as e:
            return Response({"error": e.messages}, status=status.HTTP_400_BAD_REQUEST)

        # Update password and invalidate old sessions
        user.set_password(new_password)
        user.login_token = None  # Clear OTP
        user.save()

        # Invalidate all existing sessions
        user.auth_token_set.all().delete()
        
        return Response(
            {"message": "Password updated successfully. Please login again."},
            status=status.HTTP_200_OK
        )