from marshmallow import Schema, fields, validate


class ErrorSchema(Schema):
    error = fields.String()
    error_description = fields.String()
    code = fields.Integer(dump_default=None)


class SuccessMessageSchema(Schema):
    message = fields.String()


class PaginationQuerySchema(Schema):
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))
