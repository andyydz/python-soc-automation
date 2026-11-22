import copy
import pytest

from soc_automation.investigation.builder import build_investigation


def test_build_investigation_linux_fim_no_ip_or_process_fields():
    alert = {
        "rule_id": "100002",
        "severity": 8,
        "description": "SENTINEL: File integrity modification detected in monitored home directory.",
        "agent_name": "sentinel-linux01",
        "process_images": [],
        "target_process_images": [],
        "ip_addresses": [],
    }

    inv = build_investigation(alert)

    assert inv["status"] == "new"
    assert inv["summary"] == alert["description"]
    assert inv["affected_asset"] == {
        "agent_name": "sentinel-linux01",
        "asset_identifier": None,
        "ip_address": None,
    }
    assert inv["detection_details"] == {
        "rule_id": "100002",
        "description": alert["description"],
        "severity": 8,
        "groups": [],
        "mitre_techniques": [],
        "mitre_tactics": [],
    }
    assert inv["priority"] == {
        "label": None,
        "reason": None,
        "source": None,
    }
    assert inv["case_reference"] is None
    assert inv["analyst_notes"] == []
    assert inv["evidence"] == []


def test_build_investigation_enrichment_artifacts_override():
    target = "/home/sentinel-admin/.fim_probe_test.txt"
    alert = {
        "rule_id": "100003",
        "severity": 8,
        "description": "SENTINEL: New file created in monitored home directory.",
        "agent_name": "sentinel-linux01",
    }
    enrichment = {
        "artifacts": {
            "file_paths": [target],
            "process_images": [],
            "target_process_images": [],
            "ip_addresses": [],
        }
    }

    inv = build_investigation(alert, enrichment=enrichment)

    assert inv["affected_asset"]["ip_address"] is None
    assert inv["evidence"] == [{"type": "file_paths", "value": target}]


@pytest.mark.parametrize(
    "enrichment",
    [
        None,
        {},
        {
            "rule_metadata": None,
            "severity_context": None,
            "mitre_attack": None,
        },
    ],
)
def test_build_investigation_handles_missing_or_none_enrichment(enrichment):
    alert = {
        "rule_id": "100003",
        "severity": 8,
        "description": "SENTINEL: New file created in monitored home directory.",
        "agent": "002",
    }

    inv = build_investigation(alert, enrichment=enrichment)

    assert inv["affected_asset"]["agent_name"] == "002"
    assert inv["detection_details"]["groups"] == []
    assert inv["detection_details"]["mitre_techniques"] == []
    assert inv["detection_details"]["mitre_tactics"] == []
    assert inv["priority"]["label"] is None
    assert inv["priority"]["source"] is None


def test_build_investigation_does_not_mutate_inputs():
    alert = {
        "rule_id": "100004",
        "severity": 8,
        "description": "SENTINEL: File deleted from monitored home directory.",
        "agent_name": "sentinel-linux01",
    }
    enrichment = {
        "rule_metadata": {"groups": ["syscheck", "fim"]},
        "severity_context": {"severity_label": "high", "classification_source": "rule_level"},
        "mitre_attack": {"techniques": ["T1070"], "tactics": ["Defense Evasion"]},
        "artifacts": {
            "file_paths": ["/home/sentinel-admin/.fim_probe_test.txt"],
            "process_images": [],
            "target_process_images": [],
            "ip_addresses": [],
        },
    }

    alert_snapshot = copy.deepcopy(alert)
    enrichment_snapshot = copy.deepcopy(enrichment)

    inv = build_investigation(alert, enrichment=enrichment)
    inv["detection_details"]["groups"].append("mutated")
    inv["evidence"].clear()

    assert alert == alert_snapshot
    assert enrichment == enrichment_snapshot


@pytest.mark.parametrize(
    "bad_alert,bad_enrichment,exc_type",
    [
        ("not-a-dict", None, TypeError),
        ({}, "not-a-dict", TypeError),
        ({}, {"rule_metadata": "bad"}, TypeError),
        ({}, {"severity_context": ["bad"]}, TypeError),
        ({}, {"mitre_attack": 123}, TypeError),
        ({}, {"rule_metadata": {"groups": "not-a-list"}}, TypeError),
        ({}, {"mitre_attack": {"techniques": [""]}}, ValueError),
        ({}, {"mitre_attack": {"tactics": ["   "]}}, ValueError),
        (
            {},
            {
                "artifacts": {
                    "file_paths": ["  "],
                    "process_images": [],
                    "target_process_images": [],
                    "ip_addresses": [],
                }
            },
            ValueError,
        ),
    ],
)
def test_build_investigation_validation_errors(bad_alert, bad_enrichment, exc_type):
    with pytest.raises(exc_type):
        build_investigation(bad_alert, enrichment=bad_enrichment)
