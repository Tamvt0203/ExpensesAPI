from rest_framework import serializers
from .utils import Google, register_social_user
from django.conf import settings
import logging
from rest_framework.exceptions import AuthenticationFailed

logger = logging.getLogger(__name__)

class GoogleSignInSerializer(serializers.Serializer):
    access_token = serializers.CharField(min_length=6)

    def validate_access_token(self, access_token):
        google_user_data = Google.validate(access_token=access_token)
        logger.warning("Google user data: %s", google_user_data)
        if google_user_data is None:
            raise serializers.ValidationError("Failed to validate token. It may have expired or is invalid.")
    
        if 'sub' not in google_user_data:
            raise serializers.ValidationError("Google user data is missing the 'sub' key.")


        
        # if google_user_data['aud'] != settings.GOOGLE_CLIENT_ID:
        #     raise AuthenticationFailed(detail = "could not verify client")
        email  = google_user_data['email']
        user_name = google_user_data['name']
        provider = "google"
        
        return register_social_user(username=user_name,email =  email,provider =  provider)
