import string
from django.core.mail import send_mail
from django.conf import settings
import random
from .models import UserAccount, Referral

def generate_referral_code(length=8):
    characters = string.ascii_letters + string.digits
    while True:
        code = ''.join(random.choices(characters, k=length))
        if not Referral.objects.filter(referral_code=code).exists():
            return code

def generate_code():
    code = str(random.randint(100000, 999999))
    return code

def send_email_to_user(email, code):
    subject = "Verification Code"
    message = f"Please find verification code {code}"
    from_email = settings.EMAIL_HOST_USER
    recipient = [email]
    send_mail(subject, message, from_email, recipient)