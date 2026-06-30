from marshmallow import Schema, fields, validate, validates_schema, ValidationError


class TokenRequestSchema(Schema):
    grantType = fields.String(required=True, validate=validate.OneOf(["password", "refresh_token"]))
    username = fields.String()
    password = fields.String()
    refresh_token = fields.String(data_key="refresh_token")

    @validates_schema
    def validate_grant_fields(self, data, **kwargs):
        if data["grantType"] == "password":
            if not data.get("username"):
                raise ValidationError("username is required for password grant")
            if not data.get("password"):
                raise ValidationError("password is required for password grant")
        elif data["grantType"] == "refresh_token":
            if not data.get("refresh_token"):
                raise ValidationError("refresh_token is required for refresh_token grant")


class TokenResponseSchema(Schema):
    access_token = fields.String()
    token_type = fields.String()
    expires_in = fields.Integer()
    refresh_token = fields.String(required=False)
    role = fields.String()
    attributes = fields.List(fields.String())


class SignUpRequestSchema(Schema):
    username = fields.String(required=True)
    email = fields.String(required=True)
    first_name = fields.String(required=True)
    last_name = fields.String(required=True)
    password = fields.String(required=True)
    role = fields.String(load_default="role_user")


class SignUpResponseSchema(Schema):
    message = fields.String()
    userId = fields.Integer()
    username = fields.String()
    email = fields.String()
    role = fields.String()


class CheckCredentialsRequestSchema(Schema):
    username = fields.String(required=True)
    password = fields.String(required=True)


class CheckCredentialsResponseSchema(Schema):
    message = fields.String()
    isValid = fields.Boolean()
    userId = fields.Integer()
    username = fields.String()


class ChangePasswordRequestSchema(Schema):
    newPassword = fields.String(required=True)


class ChangePasswordResponseSchema(Schema):
    message = fields.String()
    userId = fields.Integer()
    username = fields.String()


class UpdateProfileRequestSchema(Schema):
    first_name = fields.String(required=True)
    last_name = fields.String(required=True)


class UserProfileSchema(Schema):
    id = fields.Integer()
    username = fields.String()
    email = fields.String()
    first_name = fields.String()
    last_name = fields.String()
    role = fields.String()
    created_at = fields.DateTime(format="iso", allow_none=True)
    password_changed_at = fields.DateTime(format="iso", allow_none=True)


class UserListItemSchema(Schema):
    id = fields.Integer()
    username = fields.String()
    email = fields.String()
    first_name = fields.String()
    last_name = fields.String()
    role = fields.String()
    created_at = fields.DateTime(format="iso", allow_none=True)
    attributes = fields.List(fields.String())


class AttributesRequestSchema(Schema):
    attributes = fields.List(fields.String(), required=True)


class UserAttributesResponseSchema(Schema):
    user_id = fields.Integer()
    attributes = fields.List(fields.String())
    role = fields.String()


class AttributeOperationResponseSchema(Schema):
    message = fields.String()
    attributes = fields.List(fields.String())


class RevokeResponseSchema(Schema):
    message = fields.String()
