"""
Marshmallow schemas for Iris REST API request/response validation.
Fields use camelCase for JSON keys as per the project convention.
"""

from __future__ import annotations

from marshmallow import Schema, fields, validate


class AnalyzeRequestSchema(Schema):
    """Request body for ``POST /iris/analyze``."""
    title = fields.String(load_default=None, validate=validate.Length(max=120))
    headers = fields.String(required=True, validate=validate.Length(min=10))


class AnalysisIdQuerySchema(Schema):
    """Query parameter for ``GET /iris/status`` — supplied as ``?id=...``."""
    id = fields.Integer(required=True)


class ResultsQuerySchema(Schema):
    """Query parameters for the paginated results list."""
    page = fields.Integer(load_default=1, validate=validate.Range(min=1))
    per_page = fields.Integer(load_default=10, validate=validate.Range(min=1, max=100))


class AnalyzeResponseSchema(Schema):
    """Response returned immediately after submitting headers."""
    message = fields.String()
    analysisId = fields.Integer()
    status = fields.String()


class AnalysisStatusResponseSchema(Schema):
    """Current lifecycle status and optional progress of an analysis."""
    analysisId = fields.Integer()
    status = fields.String()
    progress = fields.Integer(load_default=None)
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)


class RuleResultSchema(Schema):
    """Outcome of a single rule within a finished analysis."""
    ruleName = fields.String()
    category = fields.String(load_default=None)
    score = fields.Float()
    verdict = fields.String()
    details = fields.Dict(load_default=None)
    recommendation = fields.String(load_default=None)


class AnalysisDetailResponseSchema(Schema):
    """Full analysis report: headers, per-rule results, verdict."""
    analysisId = fields.Integer()
    title = fields.String(load_default=None)
    status = fields.String()
    rawHeaders = fields.String()
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)
    startedAt = fields.String(load_default=None)
    finishedAt = fields.String(load_default=None)
    user = fields.String()
    rules = fields.List(fields.Nested(RuleResultSchema))
    recommendations = fields.List(fields.String())


class AnalysisListItemSchema(Schema):
    """Summary of a single analysis shown in a paginated list."""
    analysisId = fields.Integer()
    title = fields.String(load_default=None)
    status = fields.String()
    totalScore = fields.Float(load_default=None)
    verdict = fields.String(load_default=None)
    startedAt = fields.String(load_default=None)
    finishedAt = fields.String(load_default=None)


class AnalysisListResponseSchema(Schema):
    """Paginated list of analyses for the current user."""
    analyses = fields.List(fields.Nested(AnalysisListItemSchema))
    total = fields.Integer()
    page = fields.Integer()
    perPage = fields.Integer()


class AnalysisDeleteResponseSchema(Schema):
    """Confirmation after deleting an analysis."""
    message = fields.String()
    analysisId = fields.Integer()


class AnalysisCancelResponseSchema(Schema):
    """Confirmation after cancelling a running analysis."""
    message = fields.String()
    analysisId = fields.Integer()
    status = fields.String()
