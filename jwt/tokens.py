import hashlib
import hmac
import time

from django.core.exceptions import ObjectDoesNotExist

from .settings import MY_JWT
from cfg.settings import SECRET_KEY
from .functions import encode, payload_decode

SECRET_KEY = SECRET_KEY.encode()


class Token:
    typ = None

    def __init__(self):
        self.claims = {}
        self.payload_data = None
        self.header_data = None
        self.signature_data = None
        self.token = None

    def set_claims(self, extra_claims: dict = None, renew_exp: bool = True) -> dict:
        if extra_claims is not None:
            self.claims.update(extra_claims)

        if renew_exp:
            self.claims['exp'] = int(time.time()) + MY_JWT[self.typ.upper() + '_LIFETIME']

        return self.claims

    def set_header(self) -> dict:
        self.header_data = {'alg': MY_JWT['ALGORITHM'], 'typ': self.typ}

        return self.header_data

    def set_payload(self, extra_claims: dict = None, renew_exp: bool = True) -> dict:
        self.payload_data = self.set_claims(extra_claims, renew_exp)

        return self.payload_data

    def set_signature(self) -> str:
        header = encode(self.header_data)
        payload = encode(self.payload_data)
        self.signature_data = hmac.new(SECRET_KEY, b'.'.join([header, payload]), hashlib.sha256).hexdigest()

        return self.signature_data

    def set_token(self, extra_claims: dict = None, renew_exp: bool = True) -> str:
        self.set_header()
        self.set_payload(extra_claims, renew_exp)
        self.set_signature()
        header = encode(self.header_data).decode()
        payload = encode(self.payload_data).decode()
        self.token = '.'.join([header, payload, self.signature_data])

        return self.token

    def check_token(self, token: str) -> bool:
        try:
            exp = payload_decode(token)['exp']

        except Exception:
            return False

        return exp > time.time()


class AccessToken(Token):
    typ = 'access_token'


class RefreshToken(Token):
    typ = 'refresh_token'

    def __init__(self, model):
        super().__init__()
        self.model = model

    def remove_token(self, **kwargs) -> None:
        try:
            self.model.objects.get(**kwargs).delete()
            self.token = None

        except ObjectDoesNotExist:
            pass

    def set_token(self, extra_claims: dict = None, renew_exp: bool = True) -> str:
        sub = extra_claims['sub']
        if len(self.model.objects.filter(user_id=sub)) > 0:
            self.remove_token(user_id=sub)

        super().set_token(extra_claims, renew_exp=renew_exp)
        self.model.objects.create(token=self.token, user_id=sub, exp=self.claims['exp'])

        return self.token

    def reset_token(self, old_token) -> str:
        claims = payload_decode(old_token)
        sub = claims['sub']
        if len(self.model.objects.filter(user_id=sub)) > 0:
            self.remove_token(token=old_token)

        super().set_token(claims, renew_exp=True)
        self.model.objects.create(token=self.token, user_id=sub, exp=self.claims['exp'])
        return self.token

    def check_token(self, token: str) -> bool:
        return len(self.model.objects.filter(token=token)) == 1 and super().check_token(token)