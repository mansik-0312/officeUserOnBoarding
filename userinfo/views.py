from django.contrib.auth.hashers import make_password
from django.views.decorators.csrf import csrf_exempt
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.decorators import api_view, permission_classes
from .utils import send_email_to_user, generate_code, generate_referral_code
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from rest_framework import status
from .models import UserAccount, Referral
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from django.http import JsonResponse
from django.contrib.auth import authenticate
from rest_framework_simplejwt.exceptions import TokenError
from django.db.models import Q
from .serializers import ReferralSerializer
from .models import IsAdmin
from rest_framework.decorators import authentication_classes
from .pagination import CustomPagination

# Create your views here.

# Registration API
# On user registration, send an OTP to the registered email address.
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
                referral.status = 'pending' #Set referral status to pending
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
            # Try to mark referral if it exists — optional
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
@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    user = request.user
    email = request.data.get('email')
    print(email)
    password = request.data.get('password')
    print(password)
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
    refreshToken = str(refresh)
    accessToken = str(refresh.access_token)
    user.access_token = accessToken
    user.save()

    # refresh = RefreshToken.for_user(user)
    return JsonResponse({
        "message": "Verified",
        "user_id": user.id,
        "access": accessToken,
        # "refresh": refreshToken
        }, status=200)


@api_view(['POST', 'GET'])
@permission_classes([IsAdmin])
def admin_referral_list(request):
    # Get token from header
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
    paginator = CustomPagination()
    paginator.page_size = page_size
    result_page = paginator.paginate_queryset(referrals, request)
    serializer = ReferralSerializer(result_page, many=True)
    return paginator.get_paginated_response(serializer.data)


# Change Password API
# Accepts email or username and the new password.(Access token of user is required as permission)
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
@api_view(['POST'])
@csrf_exempt
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


@api_view(['POST'])
@csrf_exempt
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

