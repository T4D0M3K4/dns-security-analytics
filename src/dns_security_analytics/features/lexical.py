"""Pure lexical calculations over complete DNS queries."""

from collections import Counter
from dataclasses import dataclass
from math import fsum, log2


def normalize_query(query: str) -> str:
    """Lowercase and remove exactly one trailing DNS root dot."""
    return query.lower().removesuffix(".")


def character_entropy(value: str) -> float:
    """Return base-2 Shannon entropy; empty strings have entropy zero."""
    if not value:
        return 0.0
    length = len(value)
    return fsum(
        -(count / length) * log2(count / length)
        for count in Counter(value).values()
    )


@dataclass(frozen=True)
class LexicalFeatures:
    domain_length: int
    digit_count: int
    digit_ratio: float
    entropy: float


def calculate_features(query: str) -> LexicalFeatures:
    """Calculate features without modifying the source query."""
    normalized = normalize_query(query)
    length = len(normalized)
    digits = sum("0" <= character <= "9" for character in normalized)
    return LexicalFeatures(
        domain_length=length,
        digit_count=digits,
        digit_ratio=digits / length if length else 0.0,
        entropy=character_entropy(normalized),
    )
