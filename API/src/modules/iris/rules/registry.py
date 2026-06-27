"""
Iris Rule Registry — decorator-based rule registration system.

Each rule is a callable that receives a parsed headers dict and returns a
RuleResult.  Rules are registered via the @iris_rules.register() decorator
and discovered automatically when their module is imported.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


def extract_domain(email: str) -> str | None:
    """Extract the domain part from an email address string."""
    match = re.search(r"@([\w.-]+)", email)
    return match.group(1).lower() if match else None


# Public-suffix second levels we need to keep two labels of (very small,
# pragmatic list — a full PSL is overkill for a header heuristic).
_MULTI_LEVEL_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.mx", "com.br",
    "com.ar", "com.au", "com.es", "co.in", "co.nz", "com.tr", "com.co",
}


def registrable_domain(domain: str | None) -> str | None:
    """Reduce a hostname to its registrable domain (best-effort, no PSL).

    ``mail.corp.paypal.com`` -> ``paypal.com``; ``a.b.example.co.uk`` ->
    ``example.co.uk``.  Good enough to compare organisational alignment.
    """
    if not domain:
        return None
    labels = domain.strip(".").lower().split(".")
    if len(labels) < 2:
        return domain.lower()
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LEVEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def extract_display_name(from_header: str) -> str:
    """Extract the display-name portion of a ``From`` header.

    ``"ACME" <ops@acme.com>`` -> ``ACME``; a bare ``Marketing Team`` with no
    address -> ``Marketing Team``; a bare address -> ``""``.
    """
    if "<" in from_header:
        return from_header.split("<")[0].strip().strip('"').strip("'")
    name_part = from_header.strip()
    if "@" not in name_part:
        return name_part
    return ""


@dataclass
class RuleResult:
    """Result produced by a single analysis rule.

    Attributes:
        score: Numerical contribution to the overall credibility score.
               Positive = evidence of legitimacy, negative = suspicious.
        verdict: Short status string: "pass", "fail", "neutral", "error",
                 or a domain-specific variant like "softfail".
        details: Arbitrary structured data with rule-specific findings.
        recommendation: Human-readable advice shown when the rule
                        indicates a problem.  None when the rule passes.
    """
    score: float
    verdict: str
    details: Dict[str, Any] = field(default_factory=dict)
    recommendation: Optional[str] = None


class RuleRegistry:
    """Global registry that collects rules via the @register decorator.

    Rules are callables that receive a parsed header dictionary and
    return a RuleResult.  The registry is populated automatically when
    rule modules are imported — just add a new ``.py`` file under
    ``rules/`` and import it in ``rules/__init__.py``.
    """
    _rules: List[Dict] = []

    def register(self, name: str, category: str = "general",
                 description: str = "", needs_context: bool = False):
        """Decorator that registers a function as an analysis rule.

        Args:
            name: Human-readable rule name (e.g. "SPF", "DKIM").
            category: Grouping category (e.g. "authentication", "header_analysis").
            description: Detailed explanation of what the rule checks.
            needs_context: If True, the rule receives a
                ``services.message_parser.MessageContext`` (headers + body
                + links + attachments) instead of the plain ``headers``
                dict. Used by rules that inspect the full message body.

        Returns:
            A decorator that appends the function to the internal rule list.
        """
        def decorator(func: Callable) -> Callable:
            self._rules.append({
                "func": func,
                "name": name,
                "category": category,
                "description": description,
                "needs_context": needs_context,
            })
            return func
        return decorator

    def get_rules(self) -> List[Dict]:
        """Return a copy of all registered rule definitions."""
        return list(self._rules)

    def clear(self) -> None:
        """Remove all registered rules (used mainly in tests)."""
        self._rules.clear()


iris_rules = RuleRegistry()
