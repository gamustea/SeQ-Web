from marshmallow import Schema, fields, validate


class AegisGenerateRequestSchema(Schema):
    topicId = fields.Integer(required=True)
    tweaks = fields.Dict(load_default={})


class DocumentIdQuerySchema(Schema):
    id = fields.Integer(required=True)


class AegisLinkSchema(Schema):
    text = fields.String(required=True, validate=validate.Length(min=1, max=200))
    url = fields.Url(required=True, schemes={"http", "https"})


class AegisTipUpdateSchema(Schema):
    headline = fields.String(required=True, validate=validate.Length(min=1, max=150))
    body = fields.String(required=True, validate=validate.Length(min=1))
    links = fields.List(fields.Nested(AegisLinkSchema), load_default=[])


class AegisPillUpdateSchema(Schema):
    subtitle = fields.String(required=True, validate=validate.Length(min=1, max=256))
    intro = fields.String(load_default="")
    closing = fields.String(load_default="")
    contactEmail = fields.String(load_default="", validate=validate.Length(max=128))
    company = fields.String(load_default="", validate=validate.Length(max=128))
    tips = fields.List(fields.Nested(AegisTipUpdateSchema), load_default=[])


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
