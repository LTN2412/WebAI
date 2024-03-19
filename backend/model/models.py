from pydantic import BaseModel
import uuid


class User(BaseModel):
    username: str
    full_name: str | None
    email: str | None


class UserInDB(User):
    _id: uuid.UUID = uuid.uuid4()
    hashed_pwd: str


class Token(BaseModel):
    access_token: str
    token_type: str


class RefreshToken(Token):
    refresh_token: str


class TokenData(BaseModel):
    sub: str | None = None
    exp: int | None = None
    scopes: list[str] = []


class UserGoogle(BaseModel):
    user_id: int
