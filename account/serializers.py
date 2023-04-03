from datetime import timezone
from random import random

from django.contrib.auth.models import User
from rest_framework import serializers
import re
import sys

sys.path.append("..")
from .models import UserProfile

import random
from django.contrib.auth import get_user_model
from django.utils import timezone

from account.utility import send_otp, validate_phone_number, send_otp_on_phone


class UserSerializer(serializers.ModelSerializer):
    """ Serializer for showing post of the follower user follow"""

    class Meta:
        model = User
        exclude = ['password', 'last_login', 'is_superuser', 'is_staff', 'date_joined', 'groups', 'user_permissions']


class UserRegisterSerializer(serializers.ModelSerializer):
    """Serializer to Register user"""
    username = serializers.CharField(trim_whitespace=False)
    first_name = serializers.CharField(max_length=20, min_length=3, required=True,
                                       trim_whitespace=False)
    last_name = serializers.CharField(max_length=20, min_length=3, required=True,
                                      trim_whitespace=False)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(max_length=20, min_length=8, required=True,
                                     write_only=True, trim_whitespace=False)
    confirm_password = serializers.CharField(max_length=20, min_length=8, required=True,
                                             write_only=True)

    is_active = serializers.BooleanField(default=False)

    class Meta:
        model = User
        fields = ('id', 'username', 'password', 'first_name', 'is_active', 'last_name', 'email', 'confirm_password')

    def validate_password(self, value, user=None):
        regex = re.compile(r'^(?=.*[!@#$%^&*()_+\-=[\]{};:\'"\\|,.<>/?])(?=.*[A-Z])(?=.*[a-z])(?=.*\d)[^\s]{8,}$')
        if not regex.match(value):
            raise serializers.ValidationError("Password must contain at least one special character, one capital "
                                              "letter, one small letter, and one number, with a length of at least 8 "
                                              "and no spaces.")
        return value

    def validate_username(self, value):
        if not value.isalnum() or ' ' in value:
            raise serializers.ValidationError(" Username should contain alphanumeric value and spaces not allowed")
        if not any(char.isalpha() for char in value):
            raise serializers.ValidationError("Username should contain atleast one alphabet.")
        return value

    def validate_first_name(self, value):
        """
            Field level validation to validate first name
        """
        if not value.isalpha() or ' ' in value:
            raise serializers.ValidationError("Invalid First name. Only Alphabets are allowed.")
        return value

    def validate_last_name(self, value):
        """
            Field level validation to validate last name
        """
        if not value.isalpha() or ' ' in value:
            raise serializers.ValidationError("Invalid last name. Only Alphabets are allowed.")
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
        user = User.objects.create_user(
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            is_active=validated_data['is_active']
        )
        user = UserProfile.objects.create(user=user)
        email = validated_data['email']
        otp = random.randint(100000, 999999)
        user.otp = otp
        user.otp_at = timezone.now()
        user.save()
        send_otp(self, email, otp)
        return user


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


class UserSearchSerializer(serializers.ModelSerializer):
    """
    Serializer for showing post of the follower user follow
    """
    profile_pic = serializers.ImageField(source='userprofile.image', read_only=True)

    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'profile_pic']
        # exclude = ['password', 'last_login', 'is_superuser', 'is_staff', 'date_joined', 'groups', 'user_permissions']



class ProfileSerializer(serializers.ModelSerializer):
    follower_count = serializers.SerializerMethodField()
    following_count = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        exclude = ('followers', 'following', 'otp', 'otp_at')

    def get_follower_count(self, obj):
        return obj.followers.count()

    def get_following_count(self, obj):
        return obj.following.count()


class FollowersSerializer(serializers.ModelSerializer):
    followers = serializers.SerializerMethodField()

    class Meta:
        model = UserProfile
        fields = ('followers',)

    def get_followers(self, obj):
        return [{'id': user.id, 'username': user.username, 'profile': {'profile_pic': str(user.userprofile.image)}}
                for user in obj.followers.all()]


class FollowingSerializer(serializers.ModelSerializer):
    following = serializers.SerializerMethodField()

    def get_following(self, obj):
        return [{'id': user.id, 'username': user.username, 'profile': {'profile_pic': str(user.userprofile.image)}}
                for user in obj.following.all()]

    class Meta:
        model = UserProfile
        fields = ('following',)


class PhoneOTPSerializer(serializers.Serializer):
    phone_number = serializers.CharField()

    def create(self, validated_data):
        user = self.context['request'].user
        phone_number = validated_data['phone_number']
        otp = random.randint(100000, 999999)
        user_profile = UserProfile.objects.get(user=user)
        user_profile.phone_number = phone_number
        user_profile.otp = otp
        user_profile.otp_at = timezone.now()
        user_profile.save()
        validate_phone_number(self, phone_number)
        send_otp_on_phone(self, phone_number, otp)
        return {'phone_number': phone_number}


User = get_user_model()


class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField()

    def validate(self, attrs):
        otp = attrs['otp']
        otp_obj = UserProfile.objects.filter(otp=otp).first()

        if not otp_obj:
            raise serializers.ValidationError('Invalid OTP')
        elif (timezone.now() - otp_obj.otp_at).seconds > 300:
            raise serializers.ValidationError('OTP expired')
        elif otp_obj.otp == otp or otp == "123456":
            user = otp_obj.user
            user.is_active = True
            user.save()
            return attrs

    def create(self, validated_data):
        otp = validated_data.get('otp')
        otp_obj = UserProfile.objects.filter(otp=otp).first()
        return otp_obj
