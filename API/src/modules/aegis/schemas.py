from marshmallow import Schema, fields, validate


class AegisGenerateRequestSchema(Schema):
    topicId = fields.Integer(required=True)
    tweaks = fields.Dict(load_default={})


class DocumentIdQuerySchema(Schema):
    id = fields.Integer(required=True)


class ExportRequestBodySchema(Schema):
    format = fields.String(load_default="md", validate=validate.OneOf(["md", "json", "html"]))
    options = fields.Dict(load_default={})


class ExportDownloadQuerySchema(Schema):
    format = fields.String(load_default="md", validate=validate.OneOf(["md", "json", "html"]))
    inline = fields.Boolean(load_default=False)


class MarkdownExportQuerySchema(Schema):
    inline = fields.Boolean(load_default=False)
    noAlerts = fields.Boolean(load_default=False)


class GenerateResponseSchema(Schema):
    message = fields.String()
    documentId = fields.Integer()
    status = fields.String()


class DeleteDocumentResponseSchema(Schema):
    message = fields.String()
    documentId = fields.Integer()


class DocumentListResponseSchema(Schema):
    count = fields.Integer()
    documents = fields.List(fields.Dict())


class BrandsResponseSchema(Schema):
    count = fields.Integer()
    brands = fields.List(fields.Dict())


class BrandItemSchema(Schema):
    label = fields.String()
    circl_vendor = fields.String()
    circl_product = fields.String()
    aliases = fields.List(fields.String())


class BrandsCatalogResponseSchema(Schema):
    count = fields.Integer()
    brands = fields.List(fields.Nested(BrandItemSchema))


class FormatItemSchema(Schema):
    id = fields.String()
    name = fields.String()
    description = fields.String()
    mimetype = fields.String()
    extension = fields.String()
    features = fields.List(fields.String())
    coming_soon = fields.Boolean(load_default=False)


class ExportFormatsResponseSchema(Schema):
    default = fields.String()
    formats = fields.List(fields.Nested(FormatItemSchema))


class ExportResultResponseSchema(Schema):
    success = fields.Boolean()
    export = fields.Dict()
    document = fields.Dict()
    downloadUrl = fields.String()
