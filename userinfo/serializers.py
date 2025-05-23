from rest_framework import serializers
from .models import (UserAccount, Referral, TermsAndConditions, Follow, Faq,
                     ContactUs, StaticContent)
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
        return value

class TermsAndConditionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TermsAndConditions
        fields = '__all__'
        read_only_fields = ['version', 'created_at', 'updated_at']

class TermsAndConditionsUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = TermsAndConditions
        fields = ['content']

class FollowSerializer(serializers.ModelSerializer):
    follower_email = serializers.EmailField(source='follower.email', read_only=True)
    following_email = serializers.EmailField(source='following.email', read_only=True)

    class Meta:
        model = Follow
        fields = ['id', 'follower', 'follower_email', 'following', 'following_email']
        read_only_fields = ['created_at', 'updated_at']


class FAQCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Faq
        fields = ['question', 'answer']

    def validate_question(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("This field may not be empty.")
        if len(value) > 1000:
            raise serializers.ValidationError("Question too long (max 1000 characters).")
        if Faq.objects.filter(question__iexact=value).exists():
            raise serializers.ValidationError("This question already exists.")
        return value

    def validate_answer(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("This field may not be empty.")
        if len(value) > 2000:
            raise serializers.ValidationError("Answer too long (max 2000 characters).")
        return value

    def create(self, validated_data):
        user = self.context['request'].user
        return Faq.objects.create(created_by=user, **validated_data)


class FAQListSerializer(serializers.ModelSerializer):
    created_by_email = serializers.EmailField(source='created_by.email', read_only=True)

    class Meta:
        model = Faq
        fields = ['id', 'question', 'answer', 'created_by_email', 'created_at']


class FAQUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Faq
        fields = ['question', 'answer']

    def validate_question(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("This field may not be empty.")
        if len(value) > 1000:
            raise serializers.ValidationError("Question too long (max 1000 characters).")
        # Prevent false duplicate error when updating the same object
        if Faq.objects.filter(question__iexact=value).exclude(id=self.instance.id).exists():
            raise serializers.ValidationError("This question already exists.")
        return value

    def validate_answer(self, value):
        value = value.strip()
        if not value:
            raise serializers.ValidationError("This field may not be empty.")
        if len(value) > 2000:
            raise serializers.ValidationError("Answer too long (max 2000 characters).")
        return value

    def update(self, instance, validated_data):
        instance.updated_by = self.context['request'].user
        return super().update(instance, validated_data)


class ContactUsSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True, allow_blank=False)
    last_name = serializers.CharField(required=True, allow_blank=False)
    email = serializers.EmailField(required=True, allow_blank=False)
    contact_number = serializers.CharField(required=True, allow_blank=False)
    message = serializers.CharField(required=True, allow_blank=False)

    class Meta:
        model = ContactUs
        fields = ['first_name', 'last_name', 'email', 'contact_number', 'message', 'created_at']
        read_only_fields = ['created_at']

    def validate_contact_number(self, value):
        if not value.isdigit():
            raise serializers.ValidationError('Contact number should be numeric')
        return value


class StaticContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = StaticContent
        fields = ['flag', 'content']
        read_only_fields = ['flag']

