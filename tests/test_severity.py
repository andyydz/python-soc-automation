import pytest

from soc_automation.enrichment.severity import get_severity_context


@pytest.mark.parametrize(
    ("level", "expected_label"),
    [
        (0, "Ignored"),
        (1, "Low"),
        (4, "Low"),
        (5, "Medium"),
        (7, "Medium"),
        (8, "High"),
        (11, "High"),
        (12, "Critical"),
        (15, "Critical"),
    ],
)
def test_get_severity_context(level, expected_label):
    result = get_severity_context(level)

    assert result["original_level"] == level
    assert result["severity_label"] == expected_label
    assert result["classification_source"] == "python_soc_automation"


@pytest.mark.parametrize("level", [-1, 16])
def test_get_severity_context_rejects_out_of_range_levels(level):
    with pytest.raises(ValueError):
        get_severity_context(level)


@pytest.mark.parametrize("level", ["7", 7.0, True, None])
def test_get_severity_context_rejects_invalid_types(level):
    with pytest.raises(TypeError):
        get_severity_context(level)