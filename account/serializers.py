from datetime import timezone
from random import random

import phonenumbers as phonenumbers
from django.contrib.auth.models import User
from rest_framework import serializers
import re
import sys

sys.path.append("..")
from instaworld.settings import account_sid, auth_token, twilio_phone_number
from .models import UserProfile

from django.core.validators import validate_email

from django.core.mail import send_mail
import random
from django.contrib.auth import get_user_model
from django.utils import timezone

from twilio.rest import Client


class UserSerializer(serializers.ModelSerializer):
    """ Serializer for showing post of the follower user follow"""

    # profile = UserProfileSerializer(read_only=True)

    class Meta:
        model = User
        exclude = ['password', 'last_login', 'is_superuser', 'is_staff', 'date_joined', 'groups', 'user_permissions']


class UserRegisterSerializer(serializers.ModelSerializer):
    """Serializer to Register user"""
    first_name = serializers.CharField(max_length=20, min_length=3, required=True)
    last_name = serializers.CharField(max_length=20, min_length=3, required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(max_length=20, min_length=8, required=True, write_only=True)
    confirm_password = serializers.CharField(max_length=20, min_length=8, required=True, write_only=True)

    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'first_name', 'last_name', 'email', 'confirm_password')

    def validate_password(self, value):
        regex1 = re.compile('[@_!#$%^&*()<>?/}{~:]')
        if regex1.search(value) is None:
            raise serializers.ValidationError("Password should contain special character!")
        return value

    def validate(self, data):
        """
            Object level validation to check weather the given field exist or not and to match passwords
        """
        email = data.get('email')
        password = data.get('password')
        c_password = data.get('confirm_password')

        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError("Email already exists!")
        if password != c_password:
            raise serializers.ValidationError("Password and confirm password does not match!")
        return data

    def create(self, validated_data):
        """
            create function to create validated user data
        """
        return User.objects.create_user(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )


class UserLogInSerializer(serializers.ModelSerializer):
    """Serializer to Login user"""
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ("username", "password")


class UserChangePasswordSerializer(serializers.ModelSerializer):
    """Serializer for changing user password"""
    new_password = serializers.CharField(max_length=20, write_only=True, style={'input_type': 'password'})
    confirm_password = serializers.CharField(max_length=20, write_only=True, style={'input_type': 'password'})

    class Meta:
        model = User
        fields = ['password', 'new_password', 'confirm_password']


class DeleteUserSerializer(serializers.ModelSerializer):
    """Serializer to delete user for User model"""

    class Meta:
        model = User
        fields = '__all__'


class ProfileSerializer(serializers.ModelSerializer):
    follower_count = serializers.SerializerMethodField()
    following_count = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        exclude = ('followers', 'user', 'following', 'otp', 'otp_at')

    def get_follower_count(self, obj):
        return obj.followers.count()

    def get_following_count(self, obj):
        return obj.following.count()


class PhoneOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField()

    def validate_phone_number(self, phone_number):
        if not phone_number:
            raise serializers.ValidationError('Phone number is required')
        if not phonenumbers.is_valid_number(phonenumbers.parse(phone_number)):
            raise serializers.ValidationError('Invalid phone number')
        return phone_number

    def create(self, validated_data):
        phone_number = validated_data['phone_number']
        otp = random.randint(100000, 999999)
        UserProfile.objects.update(phone_number=phone_number, otp=otp, otp_at=timezone.now())
        self.validate_phone_number(phone_number)
        self.send_otp_on_phone(phone_number, otp)
        return {'phone_number': phone_number}

    def send_otp_on_phone(self, phone_number, otp):
        client = Client(account_sid, auth_token)

        message = f'Your OTP is: {otp}'
        verification = client.messages.create(from_=twilio_phone_number, to=phone_number, body=message)
        print(verification.status)


class EmailOTPSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=254, validators=[validate_email])

    def send_otp(self, email, otp):
        subject = 'Your OTP'
        message = f'Your OTP is: {otp}'
        from_email = 'mohd.asad@kiwitech.com'
        recipient_list = [email]
        send_mail(subject, message, from_email, recipient_list,
                  auth_user="mohd.asad@kiwitech.com", auth_password="3339khanasad")

    def create(self, validated_data):
        email = validated_data['email']
        otp = random.randint(100000, 999999)
        self.send_otp(email, otp)
        UserProfile.objects.update(otp=otp, otp_at=timezone.now())
        return {'email': email}


User = get_user_model()


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField(required=False)
    phone_number = serializers.CharField(required=False)
    otp = serializers.CharField()

    def validate(self, data):
        email = data.get('email')
        phone_number = data.get('phone_number')
        otp = data['otp']
        user = None
        if email:
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                raise serializers.ValidationError('User with this email does not exist')
        elif phone_number:
            try:
                user = UserProfile.objects.filter(phone_number=phone_number).first()
            except User.DoesNotExist:
                raise serializers.ValidationError('User with this phone number does not exist')
        else:
            raise serializers.ValidationError('Either email or phone number must be provided')
        if email is not None and otp is not None:
            otp_obj = UserProfile.objects.filter(user=user, otp=otp).last()
            if not otp_obj:
                raise serializers.ValidationError('Invalid OTP')
            if (timezone.now() - otp_obj.otp_at).seconds > 300:
                raise serializers.ValidationError('OTP expired')
        UserProfile.objects.update(is_verified=True)
        return data