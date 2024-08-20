from google.auth.transport import requests
from google.oauth2 import id_token
from authentication.models import User
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed
import logging

logger = logging.getLogger(__name__)
class Google:
    @staticmethod
    def validate(access_token):
        try:
            id_info = id_token.verify_oauth2_token(access_token, request=requests.Request())
            if "accounts.google.com" in id_info['iss']:
                return id_info

        except Exception as e:
            return "token is invalid or expired"

def register_social_user(provider, email, username):
    user = User.objects.filter(email=email)
    if user.exists():
        if provider == user[0].auth_provider:
            login_user = authenticate(email = email, password = settings.SOCIAL_AUTH_PASSWORD)
            tokens=login_user.tokens()
            return {
            'email':login_user.email,
            'username': login_user.username,
            "access_token":str(tokens.get('access')),
            "refresh_token":str(tokens.get('refresh'))
            }
        else:
            raise AuthenticationFailed(detail=f'Please login with {user[0].auth_provider}')
    else:
        new_user = {
            'username': username,
            'email': email,
            'password': settings.SOCIAL_AUTH_PASSWORD
        }
        register_user = User.objects.create_user(**new_user)
        register_user.auth_provider = provider
        register_user.is_verified = True
        register_user.save()

        login_user = authenticate(email = email, password = settings.SOCIAL_AUTH_PASSWORD)
        tokens=login_user.tokens()
        return {
            'email':login_user.email,
            'username': login_user.username,
            "access_token":str(tokens.get('access')),
            "refresh_token":str(tokens.get('refresh'))
            }
    