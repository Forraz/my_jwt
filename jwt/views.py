from rest_framework.response import Response
from rest_framework.generics import GenericAPIView
from .models import *
from .serializers import *


class TokenAPIView(GenericAPIView):
    serializer_class = TokenSerializer

    @classmethod
    def post(cls, request, *args, **kwargs):
        serializer = cls.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.validated_data)


class RefreshTokenAPIView(TokenAPIView):
    serializer_class = RefreshTokenSerializer
