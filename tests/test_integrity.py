import pytest

from soc_automation.integrity import calculate_sha256


def test_calculate_sha256_returns_64_character_hash():
    data = b"Hello SOC"

    result = calculate_sha256(data)

    assert isinstance(result, str)
    assert len(result) == 64


def test_calculate_sha256_is_consistent():
    data = b"Hello SOC"

    first_hash = calculate_sha256(data)
    second_hash = calculate_sha256(data)

    assert first_hash == second_hash


def test_calculate_sha256_changes_when_data_changes():
    first_data = b"Hello SOC"
    second_data = b"Hello SOC!"

    first_hash = calculate_sha256(first_data)
    second_hash = calculate_sha256(second_data)

    assert first_hash != second_hash


def test_calculate_sha256_rejects_non_bytes():
    with pytest.raises(TypeError):
        calculate_sha256("Hello SOC")