"""
Database models for Iris email header analysis.

IrisAnalysis stores each submitted email header analysis request, its
lifecycle status, and the final score/verdict.  IrisRuleResult stores
the output of every individual rule that was executed during the analysis.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from src.modules.shared import Base


class IrisAnalysis(Base):
    """Email header analysis request and its final result.

    Each row represents one analysis: the raw headers submitted by the
    user, the lifecycle status, and (once finished) the aggregated score
    and textual verdict.

    Attributes:
        id: Primary key, auto-incrementing integer.
        raw_headers: Original email headers as plain text.
        status: Lifecycle state — "pending", "running", "finished",
                "failed", or "cancelled".
        total_score: Sum of all rule scores once the analysis completes.
        verdict: Overall classification — "Legitimate", "Suspicious",
                 or "Phishing".
        started_at: Timestamp when the analysis was created.
        finished_at: Timestamp when the analysis reached a terminal state.
        user_id: Foreign key to the owning User.
        user: SQLAlchemy relationship to User.
        rule_results: Ordered list of IrisRuleResult (per-rule outcomes).
    """
    __tablename__ = "IrisAnalysis"

    id = Column(Integer, primary_key=True, autoincrement=True)
    raw_headers = Column(Text, nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    total_score = Column(Float, nullable=True)
    verdict = Column(String(20), nullable=True)
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("User.id"), nullable=False)
    user = relationship("User", back_populates="analyses")
    rule_results = relationship(
        "IrisRuleResult", back_populates="analysis",
        order_by="IrisRuleResult.position",
        cascade="all, delete-orphan",
    )


class IrisRuleResult(Base):
    """Outcome of a single rule during an Iris analysis.

    Stores the score, verdict, details, and optional recommendation
    produced by one rule execution.  Each analysis produces N rows
    (one per registered rule).

    Attributes:
        id: Primary key, auto-incrementing integer.
        analysis_id: Foreign key to the parent IrisAnalysis.
        rule_name: Human-readable rule name (e.g. "SPF", "DKIM").
        category: Rule category (e.g. "authentication", "header_analysis").
        score: Numerical contribution to the total credibility score.
        verdict: Rule-specific result — "pass", "fail", "neutral", etc.
        details: JSONB blob with rule-specific findings and evidence.
        recommendation: Human-readable advice for the user when the
                        rule flagged a problem; null if the rule passed.
        position: Execution order (0-based) within the analysis.
        analysis: SQLAlchemy back-reference to the parent IrisAnalysis.
    """
    __tablename__ = "IrisRuleResult"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_id = Column(Integer, ForeignKey("IrisAnalysis.id"), nullable=False)
    rule_name = Column(String(64), nullable=False)
    category = Column(String(32), nullable=True)
    score = Column(Float, nullable=False)
    verdict = Column(String(20), nullable=False)
    details = Column(JSONB, nullable=True)
    recommendation = Column(Text, nullable=True)
    position = Column(SmallInteger, nullable=False, default=0)

    analysis = relationship("IrisAnalysis", back_populates="rule_results")
