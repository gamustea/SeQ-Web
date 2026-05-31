from marshmallow import Schema, fields


class HelloResponseSchema(Schema):
    message = fields.String()
    status = fields.String()
    version = fields.String()


class CpuInfoSchema(Schema):
    percent = fields.Float()


class MemoryInfoSchema(Schema):
    total = fields.Integer()
    available = fields.Integer()
    percent = fields.Float()
    used = fields.Integer()
    free = fields.Integer()


class DiskInfoSchema(Schema):
    total = fields.Integer()
    used = fields.Integer()
    free = fields.Integer()
    percent = fields.Float()


class SystemStatusSchema(Schema):
    cpu = fields.Nested(CpuInfoSchema)
    memory = fields.Nested(MemoryInfoSchema)
    disk = fields.Nested(DiskInfoSchema)
    status = fields.String()


class ConfigUpdateSchema(Schema):
    new_config = fields.Dict(required=True)
