from django.contrib.auth.models import User
from django.db import models


class TokensModel(models.Model):
    """Модель токенов"""

    token = models.TextField()
    exp = models.IntegerField()
    user = models.OneToOneField(User, on_delete=models.CASCADE)

