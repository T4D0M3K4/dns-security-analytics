from math import log2

import pytest

from dns_security_analytics.features.lexical import (
    LexicalFeatures, calculate_features, character_entropy, normalize_query,
)


def test_normal_domain() -> None:
    features = calculate_features("chatgpt.com")
    # c and t each occur twice, seven other characters occur once.
    expected = -2 * (2 / 11) * log2(2 / 11) - 7 * (1 / 11) * log2(1 / 11)
    assert features == LexicalFeatures(11, 0, 0.0, pytest.approx(expected))


@pytest.mark.parametrize("query", ["ChatGPT.COM", "chatgpt.com.", "ChatGPT.COM."])
def test_case_and_root_dot(query: str) -> None:
    assert calculate_features(query) == calculate_features("chatgpt.com")


def test_digits() -> None:
    features = calculate_features("Ab12.test.")
    assert (features.domain_length, features.digit_count, features.digit_ratio) == (9, 2, 2 / 9)


def test_randomness_looking_string() -> None:
    features = calculate_features("a9b8c7d6e5f4g3h2")
    assert features == LexicalFeatures(16, 8, 0.5, 4.0)


@pytest.mark.parametrize("query", ["", "."])
def test_empty_normalized_query(query: str) -> None:
    assert calculate_features(query) == LexicalFeatures(0, 0, 0.0, 0.0)


def test_entropy_known_values_and_determinism() -> None:
    assert character_entropy("aaaa") == 0.0
    assert character_entropy("abab") == 1.0
    assert character_entropy("abcd") == 2.0
    values = [character_entropy("abc12.abc") for _ in range(10)]
    assert values == [values[0]] * 10
    assert character_entropy("aabbcc") == character_entropy("cbacba")


def test_normalization_does_not_strip_other_characters() -> None:
    assert normalize_query(" A.. ") == " a.. "
    assert normalize_query("A..") == "a."
    assert calculate_features("a.١２3").digit_count == 1
    assert calculate_features("a..") == LexicalFeatures(2, 0, 0.0, 1.0)
