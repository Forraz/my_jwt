from django.urls import path
from .views import TokenAPIView, RefreshTokenAPIView

urlpatterns = [
    path('token/', TokenAPIView.as_view(), name='token'),
    path('token/refresh', RefreshTokenAPIView.as_view(), name='refresh-token')
]