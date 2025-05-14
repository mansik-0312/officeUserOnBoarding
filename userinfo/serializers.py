from rest_framework import serializers
from .models import UserAccount, Referral

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