from typing import Dict
import jwt
from datetime import datetime, timezone, timedelta
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, DecodeError
from pydantic.typing import Optional, Union
from exception import JWTException, NotFoundSecret, NotFountAlgorithm, InvalidBearer
from fastapi.requests import Request
from fastapi.responses import Response
from fastexception.fastexception import FastException
from fastapi import Depends, FastAPI, Header, HTTPException, Cookie
from typing_extensions import Annotated


# request: Union[Request]
# cookie_key = _access_cookie_key
# cookie = request.cookies.get(cookie_key)


class Base:
    secret: Optional[str] = None
    algorithms: Optional[str] = "HS256"
    bearer: Optional[str] = "Bearer"
    payload: Optional[Dict] = None
    # -------------------------------
    success_message: Optional[str] = None
    expired_token_message: Optional[str] = None
    invalid_token_message: Optional[str] = None
    decode_error_message: Optional[str] = None
    # --------access token time-----------
    access_token_days: Optional[int] = 0
    access_token_hours: Optional[int] = 0
    access_token_minutes: Optional[int] = 0
    access_token_seconds: Optional[int] = 0
    # --------refresh token time-----------
    refresh_token_days: Optional[int] = 0
    refresh_token_hours: Optional[int] = 0
    refresh_token_minutes: Optional[int] = 0
    refresh_token_seconds: Optional[int] = 0


class SettingTime(Base):
    @property
    def _global_time_token(self):
        time = datetime.now(tz=timezone.utc).timestamp()
        return time

    def _use_time_default_access_token(self):
        if (
                self.access_token_days + self.access_token_hours + self.access_token_minutes + self.access_token_seconds
        ) == 0:
            now = datetime.now(tz=timezone.utc)
            time = (now + timedelta(minutes=30)).timestamp()
            return time

    @property
    def _expired_time_access_token(self):
        self._use_time_default_access_token()
        time = timedelta(days=self.access_token_days, hours=self.access_token_hours, minutes=self.access_token_minutes,
                         seconds=self.access_token_seconds)
        now = datetime.now(tz=timezone.utc)
        time = (now + time).timestamp()
        return time

    def _use_time_default_refresh_token(self):
        if (
                self.access_token_days + self.access_token_hours + self.access_token_minutes + self.access_token_seconds
        ) == 0:
            now = datetime.now(tz=timezone.utc)
            time = (now + timedelta(days=30)).timestamp()
            return time

    @property
    def _expired_time_refresh_token(self):
        self._use_time_default_access_token()
        time = timedelta(days=self.access_token_days, hours=self.access_token_hours, minutes=self.access_token_minutes,
                         seconds=self.access_token_seconds)
        now = datetime.now(tz=timezone.utc)
        time = (now + time).timestamp()
        return time


class Validate(SettingTime):

    def valid_secret(self):

        if self.secret is None:
            raise NotFoundSecret("Please enter a value for 'secret' in your class")

    def valid_algorithms(self):
        if not self.algorithms in ["HS256", "HS384", "HS512"]:
            raise NotFountAlgorithm(
                "Please enter a valid algorithm for 'algorithms' in your class or you can delete them")

    def validate_bearer(self, bearer):
        if bearer != self.bearer:
            FastException.HTTP_409_CONFLICT.http("The bearer sent with the token is incorrect")


class Auth(Validate):
    def access(self):
        self.valid_secret()
        self.valid_algorithms()
        payload = {
            # set time expired token
            "exp": self._expired_time_access_token,
            # set time create token
            "iat": self._global_time_token,
        }
        payload.update(self.payload)
        token = jwt.encode(payload=payload, key=self.secret, algorithm=self.algorithms)
        return token

    def refresh(self):
        self.valid_secret()
        self.valid_algorithms()
        payload = {
            "exp": self._expired_time_refresh_token,
            "iat": self._global_time_token,
        }
        payload.update(self.payload)
        token = jwt.encode(payload=payload, key=self.secret, algorithm=self.algorithms)
        return token

    def validate_token_jwt(self, token):
        try:
            self.valid_secret()
            self.valid_algorithms()
            jwt.decode(key=self.secret, algorithms=self.algorithms, jwt=token)
            FastException.HTTP_200_OK.http("0 : welcome ! ")

        except ExpiredSignatureError:
            FastException.HTTP_401_UNAUTHORIZED.http("1 : Json web Token is expired!")
        except InvalidSignatureError:
            FastException.HTTP_401_UNAUTHORIZED.http("2 : Json web Token is Invalid!")
        except DecodeError:
            FastException.HTTP_401_UNAUTHORIZED.http("3 : Json web Token not found!")

    def login_required(self, Authorization: Annotated[str, Header()]):
        if Authorization is None:
            FastException.HTTP_401_UNAUTHORIZED.http()
        if not Authorization:
            FastException.HTTP_401_UNAUTHORIZED.http()
        token = Authorization.split(" ")
        bearer = token[0]
        token_pure = token[1]
        self.validate_bearer(bearer)
        self.validate_token_jwt(str(token_pure))
