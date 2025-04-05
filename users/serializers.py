from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import CustomUser
from django.contrib import auth
from django.utils.crypto import get_random_string
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=100)
    is_superuser = serializers.BooleanField(default=False)
    is_staff = serializers.BooleanField(default=False)


    class Meta:
        model = CustomUser
        fields = ('username', 'full_name', 'email','gender', 'password', 'is_superuser', 'is_staff')
        
    def validate(self, attrs):
        email = attrs.get("email", '')
        username = attrs.get('username', '')
        if not username.isalnum():
            raise serializers.ValidationError(self.default_error_messages)
        return attrs
    
    def create(self, validated_data):
        # use built-in method for creating a user
        user = CustomUser.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            full_name=validated_data['full_name'],
            gender=validated_data["gender"],
            is_superuser=validated_data["is_superuser"],
            is_staff=validated_data["is_staff"],
        )
        
        # use set_password method to hash the password
        user.set_password(validated_data["password"])
        user.save()
        return user
    
class LoginSerializer(serializers.ModelSerializer):
    password=serializers.CharField(max_length=50, min_length=6, write_only=True)
    username=serializers.CharField(max_length=100, min_length=3)
    tokens=serializers.SerializerMethodField()
    
    def get_tokens(self, obj):
        user=CustomUser.objects.get(username=obj['username'])
        return user.tokens
    
    class Meta:
        model = CustomUser
        fields = ['password', 'username', 'tokens']
        
    def validate(self, attrs):
        username=attrs.get("username", '')
        password=attrs.get("password", "")
        
        # check if the username exists
        if not CustomUser.objects.filter(username=username,).exists:
            raise AuthenticationFailed('Invalid username, try again')
        
        user = auth.authenticate(username=username, password=password)
        
        if user is None:
            raise AuthenticationFailed('Account disabled, contact admin')
        
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        
        if not user.is_authorized:
            raise AuthenticationFailed("You account has not been approved by an admin")
        
        return {
            'email':user.email,
            'username': user.username,
            'tokens': user.tokens()
        }
        
        
class LogoutSerializer(serializers.ModelSerializer):
    refresh = serializers.CharField()
    
    class Meta:
        model = CustomUser
        fields = ['refresh']
    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs
    
    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError as e:
            raise serializers.ValidationError(str(e))
        
# serializers.py
class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()
    
    def validate_email(self, value):
        try:
            user = CustomUser.objects.get(email=value)
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled")
            return value
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No user found with this email")

    def save(self):
        user = CustomUser.objects.get(email=self.validated_data['email'])
        otp = get_random_string(length=6, allowed_chars='1234567890')
        user.login_token = otp
        user.save()
        return {'user': user, 'otp': otp} 
# serializers.py
# serializers.py
class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)
    confirm_password = serializers.CharField(write_only=True, min_length=8)

    def validate(self, attrs):
        # Match passwords
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match"})

        # Validate user and OTP
        user = CustomUser.objects.filter(
            email=attrs['email'],
            login_token=attrs['otp']
        ).first()

        if not user:
            raise serializers.ValidationError({"otp": "Invalid OTP or email"})

        # Check if new password is same as old
        # if user.check_password(attrs['new_password']):
        #     raise serializers.ValidationError({
        #         "new_password": "New password cannot be the same as the old password."
        #     })

        # Attach user for use in save()
        self.user = user
        return attrs

    def save(self):
        user = self.user
        user.set_password(self.validated_data['new_password'])
        user.login_token = None  # Clear OTP after password reset
        user.save()
        return user
# serializers.py
def validate(self, attrs):
    user = CustomUser.objects.filter(
        email=attrs['email'], 
        login_token=attrs['otp']
    ).first()
    
    if not user or not user.is_otp_valid():
        raise serializers.ValidationError("Invalid or expired OTP")
    
    return attrs

# users/serializers.py
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'full_name', 'gender', 'profile_picture']
        extra_kwargs = {
            'email': {'read_only': True},
        }

class PasswordChangeSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True, min_length=8)
    confirm_password = serializers.CharField(required=True, min_length=8)
    otp = serializers.CharField(required=True, max_length=6)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match"})
        return attrs