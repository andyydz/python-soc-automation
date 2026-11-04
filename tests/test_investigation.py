import copy

import pytest

from soc_automation.investigation.builder import build_investigation


@pytest.fixture
def sample_alert():
    return {
        "rule_id": "550",
        "severity": 7,
        "description": "Integrity checksum changed",
        "agent": "SENTINEL-LINUX01",
        "timestamp_original": "2026-11-04T10:30:00Z",
        "timestamp_utc": "2026-11-04T10:30:00Z",
    }


@pytest.fixture
def sample_enrichment():
    return {
        "rule_metadata": {
            "groups": ["syscheck"],
        },
        "severity_context": {
            "severity_label": "Medium",
            "classification_source": "python_soc_automation",
        },
        "mitre_attack": {
            "techniques": [],
            "tactics": [],
        },
    }


# --------------------------------------------------
# BASIC INVESTIGATION TESTS
# --------------------------------------------------


def test_build_investigation_creates_default_structure(sample_alert):
    result = build_investigation(sample_alert)

    assert result["status"] == "new"
    assert result["summary"] == "Integrity checksum changed"
    assert result["affected_asset"]["agent_name"] == "SENTINEL-LINUX01"
    assert result["priority"]["label"] is None
    assert result["case_reference"] is None
    assert result["evidence"] == []
    assert result["analyst_notes"] == []


def test_build_investigation_includes_detection_details(sample_alert):
    result = build_investigation(sample_alert)

    assert result["detection_details"]["rule_id"] == "550"
    assert result["detection_details"]["severity"] == 7
    assert result["detection_details"]["description"] == (
        "Integrity checksum changed"
    )


def test_build_investigation_uses_enrichment(
    sample_alert,
    sample_enrichment,
):
    result = build_investigation(sample_alert, sample_enrichment)

    assert result["detection_details"]["groups"] == ["syscheck"]
    assert result["priority"]["label"] == "Medium"
    assert result["priority"]["source"] == "python_soc_automation"


def test_build_investigation_preserves_mitre_context(
    sample_alert,
    sample_enrichment,
):
    sample_enrichment["mitre_attack"]["techniques"] = ["T1059"]
    sample_enrichment["mitre_attack"]["tactics"] = ["Execution"]

    result = build_investigation(sample_alert, sample_enrichment)

    assert result["detection_details"]["mitre_techniques"] == ["T1059"]
    assert result["detection_details"]["mitre_tactics"] == ["Execution"]


# --------------------------------------------------
# INPUT PRESERVATION TESTS
# --------------------------------------------------


def test_build_investigation_does_not_modify_inputs(
    sample_alert,
    sample_enrichment,
):
    original_alert = copy.deepcopy(sample_alert)
    original_enrichment = copy.deepcopy(sample_enrichment)

    build_investigation(sample_alert, sample_enrichment)

    assert sample_alert == original_alert
    assert sample_enrichment == original_enrichment


def test_build_investigation_returns_independent_lists(
    sample_alert,
    sample_enrichment,
):
    sample_enrichment["rule_metadata"]["groups"] = ["syscheck"]

    result = build_investigation(sample_alert, sample_enrichment)

    result["detection_details"]["groups"].append("modified")

    assert sample_enrichment["rule_metadata"]["groups"] == ["syscheck"]


# --------------------------------------------------
# INPUT VALIDATION TESTS
# --------------------------------------------------


def test_build_investigation_rejects_invalid_alert_type():
    with pytest.raises(TypeError):
        build_investigation("invalid")


def test_build_investigation_rejects_invalid_enrichment(sample_alert):
    with pytest.raises(TypeError):
        build_investigation(sample_alert, "invalid")


def test_build_investigation_handles_missing_optional_fields():
    result = build_investigation({
        "rule_id": "554",
        "severity": 5,
    })

    assert result["summary"] is None
    assert result["affected_asset"]["agent_name"] is None
    assert result["detection_details"]["groups"] == []
    assert result["priority"]["label"] is None


# --------------------------------------------------
# ENRICHMENT VALIDATION TESTS
# --------------------------------------------------


def test_build_investigation_rejects_invalid_rule_metadata(
    sample_alert,
):
    enrichment = {
        "rule_metadata": "invalid",
    }

    with pytest.raises(TypeError, match="rule_metadata"):
        build_investigation(sample_alert, enrichment)


def test_build_investigation_rejects_invalid_severity_context(
    sample_alert,
):
    enrichment = {
        "severity_context": [],
    }

    with pytest.raises(TypeError, match="severity_context"):
        build_investigation(sample_alert, enrichment)


def test_build_investigation_rejects_invalid_mitre_structure(
    sample_alert,
):
    enrichment = {
        "mitre_attack": "invalid",
    }

    with pytest.raises(TypeError, match="mitre_attack"):
        build_investigation(sample_alert, enrichment)


# --------------------------------------------------
# ENRICHMENT LIST VALIDATION TESTS
# --------------------------------------------------


def test_build_investigation_rejects_string_groups(sample_alert):
    enrichment = {
        "rule_metadata": {
            "groups": "syscheck",
        },
    }

    with pytest.raises(TypeError, match="groups"):
        build_investigation(sample_alert, enrichment)


def test_build_investigation_rejects_invalid_mitre_techniques(
    sample_alert,
):
    enrichment = {
        "mitre_attack": {
            "techniques": ["T1059", 123],
        },
    }

    with pytest.raises(ValueError, match="techniques"):
        build_investigation(sample_alert, enrichment)


def test_build_investigation_rejects_invalid_mitre_tactics(
    sample_alert,
):
    enrichment = {
        "mitre_attack": {
            "tactics": "Execution",
        },
    }

    with pytest.raises(TypeError, match="tactics"):
        build_investigation(sample_alert, enrichment)


def test_build_investigation_rejects_empty_string_in_groups(
    sample_alert,
):
    enrichment = {
        "rule_metadata": {
            "groups": ["syscheck", ""],
        },
    }

    with pytest.raises(ValueError, match="groups"):
        build_investigation(sample_alert, enrichment)


def test_build_investigation_rejects_empty_string_in_techniques(
    sample_alert,
):
    enrichment = {
        "mitre_attack": {
            "techniques": ["T1059", "  "],
        },
    }

    with pytest.raises(ValueError, match="techniques"):
        build_investigation(sample_alert, enrichment)