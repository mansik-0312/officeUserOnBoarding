from pydantic import ValidationError
from django.core.exceptions import ValidationError

from rest_framework import serializers
from .models import UserAccount, Referral
from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = '__all__'

class ReferralSerializer(serializers.ModelSerializer):
    referred_user_email = serializers.EmailField(source='referred_user.email', read_only=True)
    referrer_email = serializers.EmailField(source='referrer.email', read_only=True)
    class Meta:
        model = Referral
        fields = ['id', 'referred_user_email', 'referrer_email', 'status', 'created_at']

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = ['firstName', 'lastName', 'email', 'contactNumber', 'profile_picture_url', 'dateOfBirth',
                  'username', 'created_at']

class UpdateProfile(serializers.ModelSerializer):
    class Meta:
        model = UserAccount
        fields = ['firstName', 'lastName', 'dateOfBirth', 'username']

    def validate(self, data):
        for field in self.initial_data:
            if field not in self.fields:
                raise serializers.ValidationError(f"Invalid field : {field}")
            return data

class ProfilePictureUploadSerializer(serializers.Serializer):

    profile_picture_url = serializers.ImageField()

    def validate_profile_picture_url(self, value):

        max_size = 2

        if value.size > (max_size * 1024 * 1024):
            raise serializers.ValidationError(f'Image size cannot exceed {max_size} MB')