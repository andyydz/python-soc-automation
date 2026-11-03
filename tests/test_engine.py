import copy

import pytest

from soc_automation.enrichment import engine


@pytest.fixture
def sample_alert():
    return {
        "schema_version": "1.0",
        "record_type": "normalized_alert",
        "alert": {
            "rule_id": "550",
            "severity": 7,
            "description": "Integrity checksum changed",
            "agent_name": "SENTINEL-LINUX01",
            "timestamp_utc": "2026-11-03T10:30:00Z",
        },
        "raw_alert": {
            "rule": {"id": "550", "level": 7}
        },
    }


# --------------------------------------------------
# Reusable successful component responses
# --------------------------------------------------

def successful_metadata(rule_id):
    return {
        "rule_id": rule_id,
        "groups": ["syscheck"],
        "description": "File integrity event",
        "source": "local_wazuh_dataset",
    }


def successful_severity(level):
    return {
        "original_level": level,
        "severity_label": "Medium",
        "classification_source": "python_soc_automation",
    }


def successful_mitre(rule_id):
    return {
        "techniques": [],
        "tactics": [],
        "mapping_source": None,
    }


def patch_successful_components(monkeypatch):
    monkeypatch.setattr(
        engine,
        "get_rule_metadata",
        successful_metadata,
    )

    monkeypatch.setattr(
        engine,
        "get_severity_context",
        successful_severity,
    )

    monkeypatch.setattr(
        engine,
        "get_mitre_mapping",
        successful_mitre,
    )


# --------------------------------------------------
# 1. Successful enrichment
# --------------------------------------------------

def test_enrich_alert_success(sample_alert, monkeypatch):
    patch_successful_components(monkeypatch)

    result = engine.enrich_alert(sample_alert)

    assert result["schema_version"] == "1.1"
    assert result["enrichment"]["status"] == "complete"

    assert (
        result["enrichment"]["rule_metadata"]["rule_id"]
        == "550"
    )

    assert (
        result["enrichment"]["severity_context"]["severity_label"]
        == "Medium"
    )

    assert result["enrichment"]["mitre_attack"]["techniques"] == []

    assert result["enrichment"]["data_quality"]["status"] == "passed"


# --------------------------------------------------
# 2. Original alert preservation
# --------------------------------------------------

def test_original_alert_is_not_modified(
    sample_alert, monkeypatch
):
    patch_successful_components(monkeypatch)

    original = copy.deepcopy(sample_alert)

    result = engine.enrich_alert(sample_alert)

    assert sample_alert == original
    assert result is not sample_alert
    assert "enrichment" not in sample_alert
    assert "enrichment" in result


# --------------------------------------------------
# 3. Partial enrichment
# --------------------------------------------------

def test_enrichment_status_partial_when_component_fails(
    sample_alert, monkeypatch
):
    def fail_metadata(rule_id):
        raise FileNotFoundError("Rule dataset missing")

    monkeypatch.setattr(
        engine,
        "get_rule_metadata",
        fail_metadata,
    )

    monkeypatch.setattr(
        engine,
        "get_severity_context",
        successful_severity,
    )

    monkeypatch.setattr(
        engine,
        "get_mitre_mapping",
        successful_mitre,
    )

    result = engine.enrich_alert(sample_alert)

    assert result["enrichment"]["status"] == "partial"
    assert result["enrichment"]["severity_context"] is not None

    assert result["enrichment"]["provenance"]["errors"]


# --------------------------------------------------
# 4. All enrichment components unavailable
# --------------------------------------------------

def test_enrichment_status_unavailable_when_all_components_fail(
    sample_alert, monkeypatch
):
    def fail_metadata(rule_id):
        raise FileNotFoundError("Rule dataset missing")

    def fail_severity(level):
        raise ValueError("Invalid severity")

    def fail_mitre(rule_id):
        raise FileNotFoundError("MITRE dataset missing")

    monkeypatch.setattr(
        engine,
        "get_rule_metadata",
        fail_metadata,
    )

    monkeypatch.setattr(
        engine,
        "get_severity_context",
        fail_severity,
    )

    monkeypatch.setattr(
        engine,
        "get_mitre_mapping",
        fail_mitre,
    )

    result = engine.enrich_alert(sample_alert)

    assert result["enrichment"]["status"] == "unavailable"
    assert result["enrichment"]["severity_context"] is None

    assert len(
        result["enrichment"]["provenance"]["errors"]
    ) == 3


# --------------------------------------------------
# 5. Custom dataset paths
# --------------------------------------------------

def test_custom_dataset_paths_are_forwarded(
    sample_alert, monkeypatch, tmp_path
):
    rule_path = tmp_path / "custom_rules.json"
    mitre_path = tmp_path / "custom_mitre.json"

    received = {}

    def fake_metadata(rule_id, dataset_path):
        received["rule_path"] = dataset_path
        return None

    def fake_mitre(rule_id, dataset_path):
        received["mitre_path"] = dataset_path
        return successful_mitre(rule_id)

    monkeypatch.setattr(
        engine,
        "get_rule_metadata",
        fake_metadata,
    )

    monkeypatch.setattr(
        engine,
        "get_severity_context",
        successful_severity,
    )

    monkeypatch.setattr(
        engine,
        "get_mitre_mapping",
        fake_mitre,
    )

    engine.enrich_alert(
        sample_alert,
        rule_dataset_path=rule_path,
        mitre_dataset_path=mitre_path,
    )

    assert received["rule_path"] == rule_path
    assert received["mitre_path"] == mitre_path


# --------------------------------------------------
# 6. Data-quality issues are independent
# --------------------------------------------------

def test_data_quality_issues_do_not_make_enrichment_partial(
    sample_alert, monkeypatch
):
    patch_successful_components(monkeypatch)

    sample_alert["alert"]["timestamp_utc"] = None

    result = engine.enrich_alert(sample_alert)

    assert result["enrichment"]["status"] == "complete"

    assert (
        result["enrichment"]["data_quality"]["status"]
        == "issues_found"
    )


# --------------------------------------------------
# 7. Input validation
# --------------------------------------------------

@pytest.mark.parametrize(
    "invalid_alert",
    [None, [], "alert", 123],
)
def test_invalid_alert_type_rejected(invalid_alert):
    with pytest.raises(TypeError):
        engine.enrich_alert(invalid_alert)


def test_missing_alert_object_rejected():
    with pytest.raises(ValueError):
        engine.enrich_alert({
            "schema_version": "1.0"
        })


# --------------------------------------------------
# 8. Malformed Wazuh dataset
# --------------------------------------------------

def test_malformed_rule_dataset_handled_gracefully(
    sample_alert, tmp_path
):
    rule_path = tmp_path / "invalid_rules.json"

    rule_path.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    result = engine.enrich_alert(
        sample_alert,
        rule_dataset_path=rule_path,
    )

    assert result["enrichment"]["status"] == "partial"
    assert result["enrichment"]["rule_metadata"] is None

    assert result["enrichment"]["severity_context"] is not None

    errors = result["enrichment"]["provenance"]["errors"]

    assert any(
        "rule_metadata:" in error
        for error in errors
    )


# --------------------------------------------------
# 9. Malformed MITRE dataset
# --------------------------------------------------

def test_malformed_mitre_dataset_handled_gracefully(
    sample_alert, tmp_path
):
    mitre_path = tmp_path / "invalid_mitre.json"

    mitre_path.write_text(
        "{ invalid json",
        encoding="utf-8",
    )

    result = engine.enrich_alert(
        sample_alert,
        mitre_dataset_path=mitre_path,
    )

    assert result["enrichment"]["status"] == "partial"

    assert result["enrichment"]["severity_context"] is not None

    assert (
        result["enrichment"]["mitre_attack"]["techniques"]
        == []
    )

    errors = result["enrichment"]["provenance"]["errors"]

    assert any(
        "mitre_attack:" in error
        for error in errors
    )


# --------------------------------------------------
# 10. Both datasets unavailable
# --------------------------------------------------

def test_both_datasets_unavailable_handled_gracefully(
    sample_alert, tmp_path
):
    rule_path = tmp_path / "missing_rules.json"
    mitre_path = tmp_path / "missing_mitre.json"

    result = engine.enrich_alert(
        sample_alert,
        rule_dataset_path=rule_path,
        mitre_dataset_path=mitre_path,
    )

    assert result["enrichment"]["status"] == "partial"

    assert result["enrichment"]["rule_metadata"] is None
    assert result["enrichment"]["severity_context"] is not None

    assert result["enrichment"]["mitre_attack"] == {
        "techniques": [],
        "tactics": [],
        "mapping_source": None,
    }

    errors = result["enrichment"]["provenance"]["errors"]

    assert len(errors) == 2

    assert any(
        "rule_metadata:" in error
        for error in errors
    )

    assert any(
        "mitre_attack:" in error
        for error in errors
    )