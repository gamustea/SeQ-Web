"""Tests unitarios de validación de schemas Marshmallow."""

import pytest
from marshmallow import ValidationError

from src.modules.shared.schemas import PaginationQuerySchema
from src.modules.users.schemas import SignUpRequestSchema, TokenRequestSchema

pytestmark = pytest.mark.unit


# ------------------------------------------------------------- TokenRequestSchema

def test_password_grant_valid():
    data = TokenRequestSchema().load(
        {"grantType": "password", "username": "alice", "password": "x"}
    )
    assert data["grantType"] == "password"


def test_password_grant_requires_username_and_password():
    with pytest.raises(ValidationError):
        TokenRequestSchema().load({"grantType": "password", "username": "alice"})


def test_refresh_grant_requires_token():
    with pytest.raises(ValidationError):
        TokenRequestSchema().load({"grantType": "refresh_token"})


def test_refresh_grant_valid():
    data = TokenRequestSchema().load(
        {"grantType": "refresh_token", "refresh_token": "abc"}
    )
    assert data["refresh_token"] == "abc"


def test_invalid_grant_type_rejected():
    with pytest.raises(ValidationError):
        TokenRequestSchema().load({"grantType": "client_credentials"})


# ------------------------------------------------------------ PaginationQuerySchema

def test_pagination_defaults():
    data = PaginationQuerySchema().load({})
    assert data["page"] == 1
    assert data["per_page"] == 10


def test_pagination_rejects_zero_page():
    with pytest.raises(ValidationError):
        PaginationQuerySchema().load({"page": 0})


def test_pagination_rejects_per_page_above_max():
    with pytest.raises(ValidationError):
        PaginationQuerySchema().load({"per_page": 101})


# -------------------------------------------------------------- SignUpRequestSchema

def test_signup_requires_mandatory_fields():
    with pytest.raises(ValidationError):
        SignUpRequestSchema().load({"username": "bob"})


def test_signup_defaults_role_to_user():
    data = SignUpRequestSchema().load({
        "username": "bob",
        "email": "bob@x.com",
        "first_name": "Bob",
        "last_name": "Stone",
        "password": "secret",
    })
    assert data["role"] == "role_user"
