import pytest

from soc_automation.normalizer import normalize_timestamp


# 1. Convert an offset timestamp to UTC
def test_normalize_timestamp_with_offset():
    result = normalize_timestamp("2026-11-03T12:30:00+05:30")

    assert result["timestamp_utc"] == "2026-11-03T07:00:00Z"
    assert result["warnings"] == []


# 2. Preserve an already-UTC timestamp
def test_normalize_utc_timestamp():
    result = normalize_timestamp("2026-11-03T07:00:00Z")

    assert result["timestamp_utc"] == "2026-11-03T07:00:00Z"
    assert result["warnings"] == []


# 3. Handle a missing timestamp
def test_normalize_missing_timestamp():
    result = normalize_timestamp(None)

    assert result["timestamp_utc"] is None
    assert len(result["warnings"]) == 1


# 4. Handle an invalid timestamp
def test_normalize_invalid_timestamp():
    result = normalize_timestamp("not-a-timestamp")

    assert result["timestamp_utc"] is None
    assert len(result["warnings"]) == 1


# 5. Reject a timestamp without timezone information
def test_normalize_timestamp_without_timezone():
    result = normalize_timestamp("2026-11-03T12:30:00")

    assert result["timestamp_utc"] is None
    assert len(result["warnings"]) == 1


# 6. Reject an invalid input type
@pytest.mark.parametrize("timestamp", [12345, True, [], {}])
def test_reject_invalid_timestamp_type(timestamp):
    with pytest.raises(TypeError):
        normalize_timestamp(timestamp)