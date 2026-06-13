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


class TaskSchema(Schema):
    id = fields.String()
    name = fields.String()
    category = fields.String()
    externalId = fields.String(allow_none=True)
    status = fields.String()
    progress = fields.Integer()
    createdAt = fields.String(allow_none=True)
    startedAt = fields.String(allow_none=True)
    finishedAt = fields.String(allow_none=True)
    error = fields.String(allow_none=True)


class TaskQueueStatusSchema(Schema):
    maxWorkers = fields.Integer()
    aliveWorkers = fields.Integer()
    runningCount = fields.Integer()
    pendingCount = fields.Integer()
    historyCount = fields.Integer()


class TaskQueueConfigSchema(Schema):
    max_workers = fields.Integer(required=True)


class TaskPaginationQuerySchema(Schema):
    page = fields.Integer(load_default=1, validate=lambda n: n >= 1)
    per_page = fields.Integer(load_default=20, validate=lambda n: 1 <= n <= 100)
    category = fields.String(load_default=None)
    status = fields.String(load_default=None)
