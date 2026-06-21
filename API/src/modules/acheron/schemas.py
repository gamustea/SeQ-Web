from marshmallow import Schema, fields, validate, validates_schema, ValidationError


class StorableCreateSchema(Schema):
    kind = fields.String(required=True, validate=validate.OneOf(["account", "creditcard"]))
    title = fields.String()
    internalId = fields.String()
    createdAt = fields.String()
    updatedAt = fields.String()
    username = fields.String()
    domain = fields.String()
    password = fields.String()
    cardHolderName = fields.String()
    cardNumber = fields.String()
    expirationDate = fields.String()
    postalCode = fields.String()
    cvv = fields.String()

    @validates_schema
    def validate_kind_fields(self, data, **kwargs):
        if data["kind"] == "account":
            for f in ("username", "domain", "password"):
                if not data.get(f):
                    raise ValidationError(f"{f} is required for account storables")
        elif data["kind"] == "creditcard":
            for f in ("cardHolderName", "cardNumber", "expirationDate", "postalCode", "cvv"):
                if not data.get(f):
                    raise ValidationError(f"{f} is required for creditcard storables")


class StorableDeleteSchema(Schema):
    internalId = fields.String(required=True)


class BulkOperationSchema(Schema):
    internalId = fields.String(required=True)
    changes = fields.Dict(keys=fields.String(), required=True)


class VaultUpsertResponseSchema(Schema):
    message = fields.String()
    vaultId = fields.Integer()


class StorableResponseSchema(Schema):
    message = fields.String()
    storableId = fields.Integer()
    internalId = fields.String()
    vaultId = fields.Integer()
    kind = fields.String()


class BulkUpdateResponseSchema(Schema):
    message = fields.String()
    results = fields.List(fields.Raw())
