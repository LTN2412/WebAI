from model.database import HASH_ALGORITHM, JWT_ALGORITHM, SECRET_KEY, TOKEN_URL, db
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, ExpiredSignatureError, jwt
from pydantic import ValidationError
from model.models import UserInDB, TokenData
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Annotated
from pymongo.database import Database
import requests
not_username_pwd = HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                 detail='Incorrect username or password')
pwd_context = CryptContext(schemes=[HASH_ALGORITHM], deprecated='auto')
oauth2 = OAuth2PasswordBearer(tokenUrl=TOKEN_URL,
                              scopes={'user': 'user', 'item': 'item'})


def get_user(db: Database, username: str):
    return db.User.find_one({'username': username})


def get_hashed_pwd(pwd: str):
    return pwd_context.hash(pwd)


def authenticate_user(db: Database, username: str, pwd: str):
    user = get_user(db, username)
    if user:
        if not pwd_context.verify(pwd, user['hashed_pwd']):
            return None
    return user


def create_access_token(data: dict, minutes: int):
    encode_data = data.copy()
    exp = datetime.utcnow()+timedelta(seconds=minutes)
    encode_data['exp'] = exp
    return jwt.encode(encode_data, key=SECRET_KEY, algorithm=JWT_ALGORITHM)


def get_current_user(security_scopes: SecurityScopes, access_token: Annotated[str, Depends(oauth2)]):
    if security_scopes.scope_str:
        authenticate_value = f'Bearer scopes=:"{security_scopes.scope_str}"'
    else:
        authenticate_value = 'Bearer'
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                         detail='Could not validate credentials',
                                         headers={'WWW-Authenticate': authenticate_value})
    try:
        payload = jwt.decode(access_token, key=SECRET_KEY,
                             algorithms=[JWT_ALGORITHM])
        token_data = TokenData(**payload)
    except JWTError as e:
        if isinstance(e, ExpiredSignatureError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            raise credential_exception
    username = token_data.sub
    user = get_user(db, username)
    if not user:
        raise credential_exception
    for scope in security_scopes.scopes:
        if scope not in token_data.scopes:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Not enough permission',
                                headers={'WWW-Authenticate': authenticate_value})
    return user


def get_new_access_token(refresh_token: Annotated[str, Depends(oauth2)]):
    try:
        payload = jwt.decode(refresh_token, key=SECRET_KEY,
                             algorithms=[JWT_ALGORITHM])

    except JWTError as e:
        if isinstance(e, ExpiredSignatureError):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
        else:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail='Could not validate credentials',
                                headers={'WWW-Authenticate': 'Bearer'})
    access_token = create_access_token({
        'sub': payload['sub'],
        'scopes': payload['scopes']
    }, minutes=15)
    return {'access_token': access_token,
            'token_type': 'Bearer'}


def signup_user(username: str, pwd: str, full_name: str, email: str):
    if db.User.find_one({'username': username}) == None:
        user = UserInDB(username=username, hashed_pwd=get_hashed_pwd(pwd),
                        full_name=full_name, email=email)
        db.User.insert_one(dict(user))
    else:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail='Username already have')


def check_valid_token(access_token: Annotated[str, Depends(oauth2)]):
    try:
        res = requests.post(
            f'https://www.googleapis.com/oauth2/v3/tokeninfo?access_token={access_token}')
        if (res.json()):
            return res.json()
    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Token invalid')


def get_user_GG(res: Annotated[dict, Depends(check_valid_token)]):
    if db.GG.find_one({'user_id': res['sub']}) == None:
        db.GG.insert_one({
            'user_id': res['sub'],
            'email': res['email'],
            'scope': res['scope']
        })
        return {
            'ok': 'ok'
        }
    else:
        return db.GG.find_one({'user_id': res['sub']}, {'_id': 0})
