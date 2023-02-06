from django.contrib.auth.models import User
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .settings import MY_JWT
from .tokens import AccessToken
from .functions import payload_decode

header_name = MY_JWT['HEADER_NAME']


class JWTAuthentication(BaseAuthentication):
    token_obj = AccessToken()

    def authenticate(self, request):
        self.check_headers(request.headers)
        token = request.headers[header_name]
        self.token_authenticate(token)
        user_id = self.token_obj.payload_data['sub']

        return User.objects.get(id=user_id), token

    def token_authenticate(self, token):
        payload = payload_decode(token)
        self.token_obj.set_token(payload, renew_exp=False)
        if token != self.token_obj.token or not self.token_obj.check_token(token):
            raise AuthenticationFailed('Неверный или просроченный токен.')

    @staticmethod
    def check_headers(headers):
        if header_name not in headers.keys():
            raise AuthenticationFailed(f'Хедер {header_name} отсутствует в запросе.')
