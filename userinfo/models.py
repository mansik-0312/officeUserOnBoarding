from django.db import models
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import AbstractBaseUser
import uuid
from django.db.models import ForeignKey
from typing import cast
from django.utils import timezone
from rest_framework.permissions import BasePermission



class IsAdmin(BasePermission):
    def has_permission(self, request, view):
        # Ensure the user is authenticated and is an admin
        return bool(request.user and request.user.is_authenticated and request.user.is_admin)


# Create your models here.
class UserAccount(AbstractBaseUser):

    id = models.AutoField(primary_key=True)
    firstName = models.CharField(max_length=50)
    lastName = models.CharField(max_length=50)
    email = models.EmailField(max_length=100, unique=True)
    dateOfBirth = models.DateField()
    contactNumber = models.IntegerField()
    username = models.CharField(max_length=50, unique=True)
    # password = models.CharField(max_length=50)
    verification_code = models.CharField(max_length=6, blank=True)
    confirm_password = models.CharField(max_length=50, null=True, blank=True)
    new_password = models.CharField(max_length=50, null=True, blank=True)
    access_token = models.CharField(max_length=500, null=True, blank=True)
    referral_code = models.CharField(max_length=50, null=True, blank=True)
    is_admin = models.BooleanField(default=True)

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