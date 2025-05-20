from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
import uuid
from django.db.models import ForeignKey
from typing import cast
from django.utils import timezone
from pydantic import ValidationError
from rest_framework.permissions import BasePermission
from django.contrib.auth.models import BaseUserManager


class UserAccountManager(BaseUserManager):
    def create_user(self, email, username, password=None, **extra_fields):
        if not email:
            raise ValueError('Users must have an email address')
        email = self.normalize_email(email)
        user = self.model(email=email, username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, username, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_admin', True)  # Optional: your custom flag
        return self.create_user(email, username, password, **extra_fields)


class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        # Ensure the user is authenticated and is an admin
        return bool(request.user and request.user.is_authenticated and request.user.is_admin)

# Create your models here.
class UserAccount(AbstractBaseUser, PermissionsMixin):

    id = models.AutoField(primary_key=True)
    firstName = models.CharField(max_length=50)
    lastName = models.CharField(max_length=50)
    email = models.EmailField(max_length=100, unique=True)
    dateOfBirth = models.DateField()
    contactNumber = models.CharField(max_length=10)
    username = models.CharField(max_length=50, unique=True)
    # password = models.CharField(max_length=50)
    verification_code = models.CharField(max_length=6, blank=True)
    confirm_password = models.CharField(max_length=50, null=True, blank=True)
    new_password = models.CharField(max_length=50, null=True, blank=True)
    access_token = models.CharField(max_length=500, null=True, blank=True)
    referral_code = models.CharField(max_length=50, null=True, blank=True)
    is_admin = models.BooleanField(default=False)
    profile_picture_url = models.ImageField(upload_to="profilepicture", null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)  # Add this line
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = UserAccountManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username', 'firstName', 'lastName']

    def __str__(self):
        return self.email


class Referral(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),  # Code used but not verified
        ('active', 'Active'),    # Verified after signup
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    referrer = models.ForeignKey(
        UserAccount,
        on_delete=models.CASCADE,
        related_name='referrals_made'
    )
    referred_user = models.ForeignKey(
        UserAccount,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='referral_used'
    )
    referral_code = models.CharField(max_length=20, unique=True)
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    verified_at = models.DateTimeField(null=True, blank=True)

    def mark_verified(self):
        self.status = 'active'
        self.verified_at = timezone.now()
        self.save()

    def __str__(self):
        referrer = cast(UserAccount, self.referrer)
        return f"{referrer.email} -> {self.referral_code} [{self.status}]"

class TermsAndConditions(models.Model):
    STATUS_CHOICES = [
        ('ENABLED', 'Enabled'),
        ('DISABLED', 'Disabled'),
    ]

    content = models.TextField()
    version = models.CharField(max_length=10, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='DISABLED')

    def __str__(self):
        return f"Version {self.version} - {self.status}"

class Follow(models.Model):

    follower = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='follower_set')
    following = models.ForeignKey(UserAccount, on_delete=models.CASCADE, related_name='following_set')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def clean(self):
        if self.follower == self.following:
            raise ValidationError("You cannot follow yourself")
        if Follow.objects.filter(follower=self.follower, following=self.following).exists():
            raise ValidationError("Already exists")

    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.follower} follows {self.following}"

class Faq(models.Model):
    question = models.TextField()
    answer = models.TextField()
    created_by = models.ForeignKey(
        UserAccount,
        on_delete=models.CASCADE,
        related_name='created_faqs'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_by = models.ForeignKey(
        UserAccount,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='updated_faqs'
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.question


