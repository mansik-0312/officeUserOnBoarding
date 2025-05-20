from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.decorators import api_view, permission_classes, authentication_classes, parser_classes
from rest_framework.exceptions import ValidationError
from rest_framework.generics import ListAPIView
from rest_framework.parsers import JSONParser
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from .utils import send_email_to_user, generate_code, generate_referral_code
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework import status
from .models import UserAccount, Referral, TermsAndConditions, Follow, Faq
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.http import JsonResponse
from django.contrib.auth import authenticate
from rest_framework_simplejwt.exceptions import TokenError
from django.db.models import Q
from .serializers import FAQUpdateSerializer, FAQListSerializer, FAQCreateSerializer, FollowSerializer, TermsAndConditionsUpdateSerializer, TermsAndConditionsSerializer, ReferralSerializer, UserProfileSerializer, UpdateProfile, ProfilePictureUploadSerializer
from .models import IsAdmin
# from .pagination import CustomPagination
from django.utils import timezone
from django.http import HttpResponse
from decimal import Decimal, InvalidOperation
from rest_framework import status, permissions
from django.db import transaction, IntegrityError
from rest_framework import filters
from .pagination import CustomTermsPagination


# Create your views here.

# Registration API
# On user registration, send an OTP to the registered email address.
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def signup(request):
    try:
        data = request.data

        # Ensure required fields are present
        required_fields = ['firstName', 'lastName', 'email', 'dateOfBirth', 'contactNumber', 'username', 'password']
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            return Response({"error": f"Missing fields: {', '.join(missing_fields)}"},
                            status=status.HTTP_400_BAD_REQUEST)

        firstName = data['firstName']
        lastName = data['lastName']
        email = data['email']
        dateOfBirth = data['dateOfBirth']
        contactNumber = data['contactNumber']
        username = data['username']
        password = data['password']
        referral_code_input = data.get('referral_code')
        is_admin  = data.get('is_admin', False)

        verification_code = generate_code()
        print("Generated Code (to be saved and emailed):", verification_code)
        unique_code = generate_referral_code()

        new_user = UserAccount(
            firstName=firstName,
            lastName=lastName,
            email=email,
            dateOfBirth=dateOfBirth,
            contactNumber=contactNumber,
            username=username,
            verification_code=verification_code,
            referral_code=unique_code,
            is_admin=is_admin,
        )
        # Validate for duplicate user
        if UserAccount.objects.filter(username=username).exists():
            return Response({"error": "Username already exists"}, status=400)
        if UserAccount.objects.filter(email=email).exists():
            return Response({"error": "Email already exists"}, status=400)

        new_user.set_password(password)
        new_user.save()

        # Create Referral for new user
        Referral.objects.create(
            referrer=new_user,
            referral_code=unique_code,
            status='pending'
        )

        # Handle incoming referral
        if referral_code_input:
            try:
                referral = Referral.objects.get(referral_code=referral_code_input, referred_user__isnull=True) #Validate referral code (must exist and be unused).
                referral.referred_user = new_user #link referred_user to current user in referral record.
                referral.status = 'pending'
                referral.save()
            except Referral.DoesNotExist:
                return Response({"error": "Invalid referral code"}, status=400)

        send_email_to_user(email, verification_code)
        print("Stored code in DB:", new_user.verification_code)

        return Response({"message": "Signup successful. Verification email sent.",
                         "user_id": new_user.id,
                         "is_admin": new_user.is_admin,
                         "code": verification_code }, status=status.HTTP_201_CREATED)

    except KeyError as e:
        return Response({"error": f"Missing field: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def verify(request):
    email = request.data.get('email')
    user_input_code = request.data.get('code')

    if not email or not user_input_code:
        return JsonResponse({"error": "Email and verification code are required."}, status=400)

    try:
        user = UserAccount.objects.get(email=email)
        if str(user.verification_code).strip() == str(user_input_code).strip():
            try:
                referral = Referral.objects.get(referred_user=user)
                referral.mark_verified()  # sets status='active' and updates verified_at
                print(f"Referral Status: {referral.status}, Verified At: {referral.verified_at}")
            except Referral.DoesNotExist:
                print("No referral to verify — continuing anyway.")

            return JsonResponse({"message": "Verified"}, status=200)
        else:
            return JsonResponse({"error": "Enter correct verification code"}, status=400)

    except UserAccount.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

# Login API
# Accepts email and password.
# On successful validation, send an OTP to the user’s registered email for login verification.
@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    user = request.user
    email = request.data.get('email')
    password = request.data.get('password')
    if not email or not password:
        return Response({"error": "Email and password required"}, status=400)

    user = authenticate(username=email, password=password)

    print(user)

    if user is None:
        return Response({"error": "Invalid credentials"}, status=401)

    # You can still generate and send a verification code if needed
    verification_code = generate_code()
    user.verification_code = verification_code
    user.save()
    send_email_to_user(email, verification_code)

    return Response({
        "message": "Login successful. Verification code sent to email.",
        "user_id": user.id,
        "username" : user.username,
        "code": verification_code
    })

# Verify Login OTP API
# Accepts OTP and user ID.
# On success, return access and refresh tokens.

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def loginverify(request):
    email = request.data.get('email')
    user_input_code = request.data.get('user_input_code')

    if not email or not user_input_code:
        return JsonResponse({"error": "user_id and code are required"}, status=400)

    try:
        user = UserAccount.objects.get(email=email)
    except UserAccount.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

    if str(user.verification_code).strip() != str(user_input_code).strip():
        return JsonResponse({"error": "Invalid verification code"}, status=400)

    # Generate JWT token
    refresh = RefreshToken.for_user(user)
    accessToken = str(refresh.access_token)
    user.access_token = accessToken
    user.refresh_token = refresh
    user.save()

    # refresh = RefreshToken.for_user(user)
    return JsonResponse({
        "message": "Verified",
        "user_id": user.id,
        "access": accessToken,
        "refresh_token": str(refresh)
        }, status=200)

@csrf_exempt
@api_view(['POST', 'GET'])
@permission_classes([IsAdmin])
def admin_referral_list(request):
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)

    token_str = auth_header.replace('Bearer ', '').strip()

    try:
        token = AccessToken(token_str)
        user_id = token['user_id']
        user = UserAccount.objects.get(id=user_id)
        request.user = user
    except Exception as e:
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_401_UNAUTHORIZED)

    # Check if the user is admin
    if not request.user.is_admin:
        return Response({"error": "Access denied. Admins only."}, status=status.HTTP_403_FORBIDDEN)

    # Filtering and searching
    search_query = request.query_params.get('search') or request.data.get('search')
    status_filter = request.query_params.get('status') or request.data.get('status')
    page_size = request.query_params.get('page_size') or request.data.get('page_size')

    referrals = Referral.objects.all()

    if status_filter:
        referrals = referrals.filter(status=status_filter)

    if search_query:
        referrals = referrals.filter(
            Q(referrer__username__icontains=search_query) |
            Q(referrer__email__icontains=search_query) |
            Q(referred_user__username__icontains=search_query) |
            Q(referred_user__email__icontains=search_query)
        )
    if not referrals.exists():
        return Response({
            "message": "No record found"
        }, status=status.HTTP_200_OK)

    # Pagination
    paginator = CustomTermsPagination()
    paginator.page_size = page_size
    result_page = paginator.paginate_queryset(referrals, request)
    serializer = ReferralSerializer(result_page, many=True)
    return paginator.get_paginated_response(serializer.data)

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def userProfileData(request):
    auth_header = request.headers.get('Authorization')

    if not auth_header or not auth_header.startswith('Bearer '):
        return Response({"error": "Authorization token required"}, status=status.HTTP_401_UNAUTHORIZED)

    token_str = auth_header.replace('Bearer ', '').strip()

    try:
        token = AccessToken(token_str)
        user = UserAccount.objects.get(id=token['user_id'])
    except Exception:
        return Response({"error": "Invalid or expired token"}, status=status.HTTP_401_UNAUTHORIZED)

    serializer = UserProfileSerializer(user, context={'request': request})
    return Response(serializer.data)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def updateUserProfile(request):
    user = request.user

    serializer = UpdateProfile(user, data=request.data, partial=True)

    if serializer.is_valid():
        serializer.save(updated_at=timezone.now())
        return Response(serializer.data, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def profilePictureUpload(request):
    user = request.user

    serializer = ProfilePictureUploadSerializer(data=request.data)

    if serializer.is_valid():
        profile_picture = serializer.validated_data['profile_picture_url']
        print('Uploaded file:', profile_picture)

        if user.profile_picture_url:
            print('Deleting old picture:', user.profile_picture_url.name)
            user.profile_picture_url.delete(save=False)

        user.profile_picture_url = profile_picture
        user.save()

        # Dynamically build the server URL from request
        scheme = request.scheme
        host = request.get_host()
        server_url = f"{scheme}://{host}"

        image_url = f"{server_url}{user.profile_picture_url.url}" if user.profile_picture_url else None
        print('Saved new profile picture:', user.profile_picture_url.name)

        return Response({
            'message': 'Profile picture uploaded successfully',
            'profile_picture_url': image_url
        }, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@csrf_exempt
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):

    refresh_token = request.data.get('refresh_token')

    if not refresh_token:
        return Response ({'message': 'Refresh Token is required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = RefreshToken(refresh_token)
        token.blacklist()

        # user = request.user
        # user.access_token = None
        # user.save()
        return Response({'message': 'Logout successful',
                         'refresh': refresh_token
                         }, status=status.HTTP_200_OK)
    except TokenError:
        return Response({"error": "Invalid token"}, status=status.HTTP_401_UNAUTHORIZED)

@csrf_exempt
@api_view(['POST'])
@permission_classes([AllowAny])
def check_token_status(request):
    refresh_token = request.data.get("refresh_token")
    print("Refresh token", refresh_token)
    if not refresh_token:
        print("No refresh token provided")
        return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

    try:
        token = RefreshToken(refresh_token)
        print("Token JTI:", token['jti'])
        return Response({"message": "Token is valid"}, status=200)

    except TokenError as e:
        # This includes "Token is blacklisted" or "Token is invalid or expired"
        print("TokenError:", str(e))
        return Response({
            "detail": str(e),
            "code": "token_not_valid"
        }, status=status.HTTP_401_UNAUTHORIZED)


# Change Password API
# Accepts email or username and the new password.(Access token of user is required as permission)
@csrf_exempt
@api_view(['POST'])
def changePassword(request):
    # Get data from the request
    email_or_username = request.data.get('email_or_username')
    new_password = request.data.get('new_password')
    jwt_token = request.headers.get('Authorization').replace('Bearer ', '')

    #return Response(request.headers.get('Authorization'), status=200)

    email = None
    username = None

    if (not email_or_username) or (not new_password) or (not jwt_token):
        #return Response(UserAccount.objects.get(id=email_or_username).access_token, status=200)
        return JsonResponse({"error": "email/username, jwt_token and new_password are required fields"}, status=400)

    # return Response(UserAccount.objects.get(id=email_or_username).access_token, status=200)

    # Try to find the user using email or username
    try:
        if email_or_username:
            if "@" in email_or_username:
                email = email_or_username
            else:
                username = email_or_username
        else:
            return JsonResponse({"error": "email or username is required"}, status=400)
        if not jwt_token:  # Check if jwt_token is passed in headers Authorization
            return JsonResponse({"error": "Authorization headers is required"}, status=400)
    except UserAccount.Error:
        return JsonResponse({"error": "User not found/Authorization failed"}, status=404)

    user = None
    if email:
        user = UserAccount.objects.get(email=email)
    else:
        user = UserAccount.objects.get(username=username)

    # Verify access token
    if jwt_token == user.access_token:
        # Update the password
        user.password = new_password
        user.save()
        return JsonResponse({"message": "Password changed successfully"}, status=200)
    else:
        return JsonResponse({"message": "Incorrect access token"}, status=400)

# Forgot Password API
# Accepts user’s email and sends an OTP for password reset.
@csrf_exempt
@api_view(['POST'])
def forgotPassword(request):
    # Try to get email from POST data, then from query params
    email = request.data.get('email') or request.POST.get('email') or request.query_params.get('email')

    if not email:
        return JsonResponse({"error": "Email is required"}, status=400)

    try:
        user = UserAccount.objects.get(email=email)
    except UserAccount.DoesNotExist:
        return JsonResponse({"error": "Invalid credentials"}, status=401)

    code = generate_code()
    user.verification_code = code
    user.save()

    send_email_to_user(email, code)
    return JsonResponse({"message": "Verification code sent"}, status=200)

@csrf_exempt
@api_view(['POST'])
def forgotPasswordVerify(request):
    email = request.data.get('email')
    otp = request.data.get('otp')
    new_password = request.data.get('new_password')

    if not all([email, otp, new_password]):
        return Response({"error": "Email, OTP, and new_password are required."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = UserAccount.objects.get(email=email)
        if user.verification_code == otp:
            user.password = make_password(new_password)  # hash the password before saving
            user.save()
            return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)
    except UserAccount.DoesNotExist:
        return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

@csrf_exempt
@api_view(['POST'])
def setNewPassword(request):
    new_password = request.data.get('new_password')
    confirm_password = request.data.get('confirm_password')
    otp = request.data.get('otp')
    auth_header = request.headers.get('Authorization')

    if not new_password or not confirm_password:
        return JsonResponse({"error": "Both password fields are required"}, status=400)

    if new_password != confirm_password:
        return JsonResponse({"error": "Passwords do not match"}, status=400)

    if not auth_header or "Bearer " not in auth_header:
        return JsonResponse({"error": "Authorization token is required"}, status=400)

    token_str = auth_header.replace("Bearer ", "").strip()

    try:
        token = AccessToken(token_str)
        user_id = token['user_id']
        user = UserAccount.objects.get(id=user_id)
    except (TokenError, UserAccount.DoesNotExist):
        return JsonResponse({"error": "Invalid or expired token"}, status=401)

    if str(user.verification_code).strip() != str(otp).strip():
        return JsonResponse({"error": "Invalid verification code"}, status=400)

    user.set_password(new_password)
    user.save()

    return JsonResponse({"message": "Password updated successfully"}, status=200)


@api_view(['POST'])
@permission_classes([IsAdmin])
def create_terms_and_conditions(request):
    content = request.data.get('content')
    if not content:
        return Response({"detail": "Content field is required."}, status=status.HTTP_400_BAD_REQUEST)

    max_retries = 5
    for attempt in range(max_retries):
        try:
            with transaction.atomic():
                last = TermsAndConditions.objects.order_by('-created_at').first()

                if last:
                    try:
                        last_version = Decimal(last.version)
                    except InvalidOperation:
                        last_version = Decimal('1')
                    new_version = last_version + Decimal('0.1')
                    # Format with 1 decimal place, remove trailing zeros (like 1.0 => 1)
                    new_version_str = f"{new_version.normalize()}"
                else:
                    new_version_str = '1'

                term = TermsAndConditions(
                    content=content,
                    version=new_version_str,
                    status='DISABLED'  # Always disabled by default
                )
                term.save()

                serializer = TermsAndConditionsSerializer(term)
                return Response(serializer.data, status=status.HTTP_201_CREATED)

        except IntegrityError:
            # Retry if version conflict (unique constraint violation)
            if attempt == max_retries - 1:
                return Response({"detail": "Version conflict, please retry."}, status=status.HTTP_409_CONFLICT)


@api_view(['PATCH'])
@permission_classes([IsAdmin])
def update_terms_and_conditions(request, pk):
    try:
        terms = TermsAndConditions.objects.get(pk=pk)
    except TermsAndConditions.DoesNotExist:
        return Response({"detail": "Terms and Conditions not found."}, status=status.HTTP_404_NOT_FOUND)

    serializer = TermsAndConditionsUpdateSerializer(terms, data=request.data, partial=True)

    if serializer.is_valid():
        serializer.save()
        return Response({"id": terms.id,
                         "content": terms.content,
                         "version": str(terms.version),
                         "status": terms.status})
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAdmin])
def delete_terms_and_conditions(request, pk=None):
    if pk is None:
        return Response(
            {"detail": "Please provide a Terms and Conditions ID to delete."},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        terms = TermsAndConditions.objects.get(pk=pk)
    except TermsAndConditions.DoesNotExist:
        return Response(
            {"detail": "Terms and Conditions not found."},
            status=status.HTTP_404_NOT_FOUND
        )

    response_data = {
        "message": "Terms and Conditions deleted successfully.",
        "id": terms.id,
        "version": str(terms.version)
    }
    terms.delete()
    return Response(response_data, status=status.HTTP_200_OK)

@api_view(['PATCH'])
@permission_classes([IsAdmin])
def toggle_terms_status(request, pk):
    try:
        terms = TermsAndConditions.objects.get(pk=pk)
    except TermsAndConditions.DoesNotExist:
        return Response({"detail": "Terms and Conditions not found."}, status=status.HTTP_404_NOT_FOUND)

    if terms.status == "ENABLED":
        # Disable this term
        terms.status = "DISABLED"
        terms.save()
        return Response({
            "message": "Terms and Conditions disabled.",
            "id": terms.id,
            "version": str(terms.version),
            "status": terms.status
        }, status=status.HTTP_200_OK)

    # Enable this term and disable all others
    TermsAndConditions.objects.exclude(id=terms.id).update(status="DISABLED")
    terms.status = "ENABLED"
    terms.save()

    return Response({
        "message": "Terms and Conditions enabled successfully.",
        "id": terms.id,
        "version": str(terms.version),
        "status": terms.status
    }, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAdmin])
def list_terms_and_conditions(request):
    terms = TermsAndConditions.objects.all()

    # Search filter
    search_query = request.query_params.get('search')
    if search_query:
        terms = terms.filter(
            Q(content__icontains=search_query) |
            Q(version__icontains=search_query)
        )

    # Ordering filter
    ordering = request.query_params.get('ordering', '-created_at')
    terms = terms.order_by(ordering)

    # Custom pagination
    paginator = CustomTermsPagination()
    paginated_terms = paginator.paginate_queryset(terms, request)
    serializer = TermsAndConditionsSerializer(paginated_terms, many=True)
    return paginator.get_paginated_response(serializer.data)


@api_view(['GET'])
@permission_classes([AllowAny])
def get_active_terms_and_conditions(request):
    active_terms = TermsAndConditions.objects.filter(status='ENABLED').order_by('-updated_at')

    if not active_terms.exists():
        return Response(
            {"detail": "No active Terms and Conditions found."},
            status=status.HTTP_404_NOT_FOUND
        )

    data = [
        {
            "content": term.content,
            "version": str(term.version),
            "updated_at": term.updated_at
        }
        for term in active_terms
    ]

    return Response(data, status=status.HTTP_200_OK)






@api_view(['POST'])
@permission_classes([IsAuthenticated])
def follow_user(request, user_id=None):

    if user_id is None:
        return Response({"detail": "Please provide user ID to follow."}, status=status.HTTP_400_BAD_REQUEST)

    if not user_id.isdigit():
        return Response({'error': 'Invalid user ID.'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        following_user = UserAccount.objects.get(id=user_id)
    except UserAccount.DoesNotExist:
        return Response({'details': 'User does not exists'}, status=status.HTTP_400_BAD_REQUEST)

    if request.user.id == following_user.id:
        return Response({'error': 'You cannot follow yourself'}, status=status.HTTP_400_BAD_REQUEST)

    if Follow.objects.filter(follower=request.user, following=following_user).exists():
        return Response({'error': 'Already follows this user'})

    follow = Follow(follower=request.user, following=following_user)
    try:
        follow.save()
    except ValidationError as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    serializer = FollowSerializer(follow)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def unfollow_user(request, user_id=None):
    if user_id is None:
        return Response(
            {"detail": "Please provide a user ID to unfollow"},
            status=status.HTTP_400_BAD_REQUEST
        )
    if not user_id.isdigit():
        return Response({'error': 'Invalid User ID'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        following_user = UserAccount.objects.get(id=int(user_id))
    except UserAccount.DoesNotExist:
        return Response({'error': 'User does not exists'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        follow = Follow.objects.get(follower=request.user, following=following_user)
        follow.delete()
        return Response({'success': f'Unfollowed user {following_user.firstName, following_user.email}'}, status=status.HTTP_200_OK)
    except Follow.DoesNotExist:
        return Response({'error': 'You are not following this user'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_my_follower(request):

    follow = Follow.objects.filter(follower=request.user)
    if not follow.exists():
        return Response({'error': 'You have no follower'})

    serializer = FollowSerializer(follow, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_my_following(request):

    follow = Follow.objects.filter(following=request.user)
    if not follow.exists():
        return Response({'error': 'You are not following anyone'})

    serializer = FollowSerializer(follow, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAdmin])
def admin_list_follows(request):
    search = request.GET.get("search", "")
    queryset = Follow.objects.select_related("follower", "following").all()

    if search:
        queryset = queryset.filter(
            Q(follower__username__icontains=search) |
            Q(follower__email__icontains=search) |
            Q(following__username__icontains=search) |
            Q(following__email__icontains=search)
        )

    paginator = CustomTermsPagination()
    result_page = paginator.paginate_queryset(queryset, request)
    serializer = FollowSerializer(result_page, many=True)
    return paginator.get_paginated_response(serializer.data)

@api_view(['DELETE'])
@permission_classes([IsAdmin])
def delete_follow(request, user_id=None):
    if user_id is None:
        return Response(
            {"detail": "Please provide a user ID to delete follow"},
            status=status.HTTP_400_BAD_REQUEST
        )
    if not user_id.isdigit():
        return Response({'error': 'Invalid User ID'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        follow = Follow.objects.get(id=user_id)
    except Follow.DoesNotExist:
        return Response({'error': 'Follow relationship not found'}, status=status.HTTP_404_NOT_FOUND)

    follow.delete()
    return Response({'details': 'Follow relationship deleted successfully'}, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([IsAdmin])
def admin_user_follow_data(request, user_id=None):
    if user_id is None:
        return Response(
            {"detail": "Please provide a user ID to delete follow"},
            status=status.HTTP_400_BAD_REQUEST
        )
    if not user_id.isdigit():
        return Response({'error': 'Invalid User ID'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = UserAccount.objects.get(id=user_id)
    except UserAccount.DoesNotExist:
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

    follower = Follow.objects.filter(follower=user)
    following = Follow.objects.filter(following=user)

    data = {
        'follower': FollowSerializer(follower, many=True).data,
        'following': FollowSerializer(following, many=True).data
    }
    return Response(data, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAdmin])
def create_faq(request):
    serializer = FAQCreateSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        faq = serializer.save()
        return Response({
            'message': 'FAQ created successfully.',
            'faq': {
                'id': faq.id,
                'question': faq.question,
                'answer': faq.answer,
                'created_by': faq.created_by.username,
                'created_at': faq.created_at
            }
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def list_faq(request):
    search = request.GET.get('search', '')
    sort_order = request.GET.get('sort', 'desc')

    faqs = Faq.objects.all()

    if search:
        faqs = faqs.filter(question__icontains=search)

    # Sort by creation time (recommended)
    if sort_order == 'asc':
        faqs = faqs.order_by('created_at')
    else:
        faqs = faqs.order_by('-created_at')

    serializer = FAQListSerializer(faqs, many=True)
    return Response(serializer.data)

@api_view(['GET'])
@permission_classes([AllowAny])
def single_faq(request, id):
    try:
        id = int(id)  # Ensures ID is an integer
    except (ValueError, TypeError):
        return Response(
            {'error': 'Invalid FAQ ID. ID must be an integer.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    try:
        faq = Faq.objects.get(pk=id)
    except Faq.DoesNotExist:
        return Response(
            {'error': 'FAQ not found'}, status=status.HTTP_404_NOT_FOUND
        )

    serializer = FAQListSerializer(faq)
    return Response(serializer.data, status=status.HTTP_200_OK)

@api_view(['PATCH'])
@permission_classes([IsAdmin])  # Note: changed IsAdmin to IsAdminUser for standard DRF usage
def update_faq(request, id):
    try:
        faq = Faq.objects.get(pk=id)
    except Faq.DoesNotExist:
        return Response(
            {'error': 'FAQ not found'}, status=status.HTTP_404_NOT_FOUND
        )

    serializer = FAQUpdateSerializer(faq, data=request.data, partial=True, context={'request': request})
    if serializer.is_valid():
        updated_faq = serializer.save(updated_by=request.user)
        return Response({
            'message': 'FAQ updated successfully.',
            'faq': {
                'id': updated_faq.id,
                'question': updated_faq.question,
                'answer': updated_faq.answer,
                'updated_by': updated_faq.updated_by.username,
                'updated_at': updated_faq.updated_at
            }
        }, status=status.HTTP_200_OK)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['DELETE'])
@permission_classes([IsAdmin])
def delete_faq(request, id):
    try:
        faq = Faq.objects.get(pk=id)
        faq.delete()
        return Response({'message': 'FAQ deleted successfully.'}, status=status.HTTP_200_OK)
    except Faq.DoesNotExist:
        return Response({'error': 'FAQ not found'}, status=status.HTTP_404_NOT_FOUND)
