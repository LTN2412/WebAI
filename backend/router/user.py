from fastapi import Security, Depends, Form, APIRouter
from fastapi.security import OAuth2PasswordRequestForm
from model.models import RefreshToken, Token, User
from model.database import db
from dependencies import authenticate_user, create_access_token, get_new_access_token, get_current_user, signup_user, not_username_pwd
from typing import Annotated

router = APIRouter(
    prefix='/user',
    tags=['user']
)


@router.post('/token', response_model=RefreshToken)
async def login_for_access_token(login_form: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user = authenticate_user(
        db, login_form.username, login_form.password)
    if not user:
        raise not_username_pwd
    access_token = create_access_token(
        {'sub': login_form.username,
         'scopes': login_form.scopes},
        minutes=15
    )
    refresh_token = create_access_token(
        {'sub': login_form.username,
         'scopes': login_form.scopes},
        minutes=30
    )
    return {'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer'}


@router.post('/refresh-token', response_model=Token)
async def refresh_token(token: Annotated[dict, Depends(get_new_access_token)]):
    return token


@router.get('', response_model=User)
async def read_user_info(user: Annotated[User, Security(get_current_user, scopes=[])]):
    return user


@router.post('/signup')
async def signup(username: Annotated[str, Form()], pwd: Annotated[str, Form()], full_name: Annotated[str, Form()], email: Annotated[str, Form()]):
    signup_user(username=username, pwd=pwd, full_name=full_name, email=email)
    access_token = create_access_token(
        {'sub': username,
         'scopes': []},
        minutes=15
    )
    return {'access_token': access_token,
            'token_type': 'bearer'}
