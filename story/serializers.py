from rest_framework import serializers
from .models import Story
from account.models import UserProfile
from django.contrib.auth.models import User


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ('image',)


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username"]


class StorySerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    profile_pic = serializers.SerializerMethodField()
    # profile_pic = serializers.ImageField(source='userprofile.image', read_only=True)

    class Meta:
        model = Story
        fields = ('id', 'user', 'profile_pic', 'media', 'content', 'created_at', 'is_archived')
        read_only_fields = ["user", "profile_pic"]

    def get_profile_pic(self, obj):
        user = self.context['request'].user
        profile = ProfileSerializer(UserProfile.objects.get(user=user))
        return profile.data


class ArchiveStorySerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    profile_pic = serializers.SerializerMethodField()

    class Meta:
        model = Story
        fields = ('id', 'user', 'profile_pic', 'media', 'content', 'created_at', 'is_archived')
        read_only_fields = ['user', 'profile_pic']

    def get_profile_pic(self, obj):
        user = self.context['request'].user
        profile = ProfileSerializer(UserProfile.objects.get(user=user))
        return profile.data


class HighlightStorySerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    profile_pic = serializers.SerializerMethodField()

    class Meta:
        model = Story
        fields = ('id', 'user', 'profile_pic', 'media', 'content', 'created_at', 'is_archived')
        read_only_fields = ['user', 'profile_pic']

    def get_profile_pic(self, obj):
        user = self.context['request'].user
        profile = ProfileSerializer(UserProfile.objects.get(user=user))
        return profile.data
