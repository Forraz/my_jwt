from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .tokens import *
from .models import *


class TokenSerializer(serializers.Serializer):
    model = TokensModel
    access_token_obj = AccessToken()
    refresh_token_obj = RefreshToken(model)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['username'] = serializers.CharField()
        self.fields['password'] = serializers.CharField()

    def validate(self, attrs):
        username = attrs['username']
        password = attrs['password']

        try:
            user = User.objects.get(username=username)
            if not user.check_password(password):
                raise ObjectDoesNotExist

        except ObjectDoesNotExist:
            raise ValidationError('Неверное имя пользователя или пароль.')

        claims = {'sub': user.id}
        access_token = self.access_token_obj.set_token(claims)
        refresh_token = self.refresh_token_obj.set_token(claims)

        return {'access_token': access_token, 'refresh_token': refresh_token}


class RefreshTokenSerializer(serializers.Serializer):
    model = TokensModel
    refresh_token_obj = RefreshToken(model)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['refresh_token'] = serializers.CharField()

    def validate(self, attrs):
        old_token = attrs['refresh_token']
        if not self.refresh_token_obj.check_token(old_token):
            raise ValidationError("Неверный или просроченный токен.")

        refresh_token = self.refresh_token_obj.reset_token(old_token)

        return {'refresh_token': refresh_token}





