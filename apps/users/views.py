from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
import random
import string
from .models import User, OTP
from .serializers import UserSignupSerializer, UserLoginSerializer, UserProfileSerializer, OTPVerifySerializer


def generate_and_send_otp(user, purpose='signup'):
    """Generate and send OTP to user's email"""
    # Generate 6-digit OTP
    otp_code = ''.join(random.choices(string.digits, k=6))
    
    # Hash the OTP before storing
    hashed_otp = make_password(otp_code)
    
    # Create OTP record
    otp_obj = OTP.objects.create(
        user=user,
        hashed_otp=hashed_otp,
        purpose=purpose,
        expires_at=timezone.now() + timezone.timedelta(minutes=10)
    )
    
    # Send OTP via email
    subject = f'Your {purpose.title()} OTP - WasteWorth'
    message = f'Your OTP code is: {otp_code}\n\nThis code will expire in 10 minutes.'
    
    try:
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        return True
    except Exception as e:
        # Log error in production
        return False


@api_view(['POST'])
def signup(request):
    serializer = UserSignupSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        
        # Generate and send OTP immediately after user creation
        otp_sent = generate_and_send_otp(user, purpose='signup')
        
        response_data = {
            'message': 'User created successfully. Please verify your email with the OTP sent.',
            'userId': str(user.id),
            'email': user.email
        }
        
        # Add OTP note if email was sent successfully
        if otp_sent:
            response_data['note'] = 'OTP sent to email'
        else:
            response_data['error'] = 'Failed to send OTP. Please try again.'
        
        return Response(response_data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def login(request):
    serializer = UserLoginSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.validated_data['user']
        
        # Generate and send OTP after successful login
        otp_sent = generate_and_send_otp(user, purpose='login')
        
        response_data = {
            'message': 'Credentials verified. Please verify the OTP sent to your email to complete login.',
            'userId': str(user.id),
            'email': user.email
        }
        
        # Add OTP note if email was sent successfully
        if otp_sent:
            response_data['note'] = 'OTP sent to email'
        else:
            response_data['error'] = 'Failed to send OTP. Please try again.'
        
        return Response(response_data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
def verify_otp(request):
    """Verify OTP for different actions (login, signup, reset)"""
    action = request.query_params.get('action')
    
    # Validate action parameter
    valid_actions = ['login', 'signup', 'reset']
    if not action or action not in valid_actions:
        return Response({
            'error': f'Invalid or missing action. Must be one of: {", ".join(valid_actions)}'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Prepare request data
    request_data = request.data.copy()
    
    # Validate OTP using serializer
    serializer = OTPVerifySerializer(data=request_data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    user = serializer.validated_data['user']
    otp_obj = serializer.validated_data['otp_obj']
    
    # Ensure OTP purpose matches the requested action
    if otp_obj.purpose != action:
        return Response({
            'error': f'OTP purpose mismatch. Expected {action}, but OTP is for {otp_obj.purpose}'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # Mark OTP as used
    otp_obj.used = True
    otp_obj.save()
    
    # Handle password reset if action is 'reset'
    if action == 'reset':
        new_password = request.data.get('newPassword')
        if not new_password:
            return Response({
                'error': 'newPassword is required for password reset'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate password length
        if len(new_password) < 8:
            return Response({
                'error': 'Password must be at least 8 characters long'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Set new password
        user.set_password(new_password)
        user.save()
        
        return Response({
            'message': 'Password reset successful',
            'user': UserProfileSerializer(user).data
        }, status=status.HTTP_200_OK)
    
    # Handle other actions (login, signup) - NOW RETURN TOKENS
    # Mark user as verified for signup and login actions
    if action in ['signup', 'login']:
        user.is_verified = True
        user.save()
    
    refresh = RefreshToken.for_user(user)
    action_messages = {
        'login': 'Login verification successful',
        'signup': 'Account verification successful'
    }
    
    return Response({
        'message': action_messages.get(action, 'OTP verification successful'),
        'user': UserProfileSerializer(user).data,
        'tokens': {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    }, status=status.HTTP_200_OK)


@api_view(['POST'])
def request_password_reset(request):
    """Request password reset OTP"""
    email_or_phone = request.data.get('emailOrPhone')
    
    if not email_or_phone:
        return Response({
            'error': 'emailOrPhone is required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Detect if input is email or phone
        if '@' in email_or_phone:
            user = User.objects.get(email=email_or_phone)
        else:
            user = User.objects.get(phone=email_or_phone)
        
        # Generate and send OTP for password reset
        otp_sent = generate_and_send_otp(user, purpose='reset')
        
        if otp_sent:
            return Response({
                'message': 'OTP for password reset sent'
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'error': 'Failed to send OTP. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
    except User.DoesNotExist:
        # In development, be explicit about user not found
        # In production, return generic message to avoid user enumeration
        if settings.DEBUG:
            return Response({
                'error': 'No user found with this email or phone'
            }, status=status.HTTP_404_NOT_FOUND)
        else:
            # Return success message to avoid user enumeration in production
            return Response({
                'message': 'OTP for password reset sent'
            }, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    try:
        user_id = request.data.get('userId')
        refresh_token = request.data.get('refreshToken')
        auth_token = request.data.get('authToken')
        
        # Verify userId matches requesting user if provided
        if user_id:
            if str(request.user.id) != str(user_id):
                return Response({
                    'error': 'User ID does not match authenticated user'
                }, status=status.HTTP_403_FORBIDDEN)
        
        # If refreshToken is present, attempt to blacklist it
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
                return Response({
                    'message': 'Logout successful'
                }, status=status.HTTP_200_OK)
            except TokenError:
                return Response({
                    'error': 'Invalid refresh token'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # If only authToken is present, explain preference for refresh tokens
        elif auth_token:
            return Response({
                'message': 'Logout successful',
                'note': 'Refresh tokens are preferred for secure logout. Access tokens cannot be reliably invalidated.'
            }, status=status.HTTP_200_OK)
        
        # No tokens provided
        else:
            return Response({
                'error': 'Either refreshToken or authToken is required'
            }, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        return Response({
            'error': 'Logout failed'
        }, status=status.HTTP_400_BAD_REQUEST)
