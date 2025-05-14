from . import views
from django.urls import path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from .views import admin_referral_list, userProfileData

urlpatterns= [
    path("signup/", views.signup, name='signup'),
    path("verify/", views.verify, name='verify'),
    path("login/", views.login, name='login'),
    path("token/refresh/", TokenRefreshView.as_view(), name='token_refresh'),
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path("loginVerify/", views.loginverify, name='loginVerify'),
    path("changePassword/", views.changePassword, name='changePassword'),
    path("forgotPassword/", views.forgotPassword, name='forgotPassword'),
    path("forgotPasswordVerify/", views.forgotPasswordVerify,
         name='forgotPasswordVerify'),
    path('setNewPassword/', views.setNewPassword, name='set_new_password'),
    path('api/admin/referrals/', admin_referral_list, name='admin-referral-list'),
    path('userProfileData/', userProfileData, name='user-Profile-Data')
]