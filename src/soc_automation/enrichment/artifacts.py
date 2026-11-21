from typing import Any


def _add_str(bucket: set[str], value: Any) -> None:
    if isinstance(value, str):
        cleaned = value.strip()
        if cleaned:
            bucket.add(cleaned)


def extract_artifacts(record: Any) -> dict[str, list[str]]:
    """
    Extract deduplicated, sorted artifacts from a Wazuh alert or
    processed alert envelope using only fields already present in the data.

    Performs no network calls and makes no maliciousness claims.
    """
    empty: dict[str, list[str]] = {
        "file_paths": [],
        "process_images": [],
        "target_process_images": [],
        "ip_addresses": [],
    }

    if not isinstance(record, dict):
        return empty

    raw = record.get("raw_alert") if isinstance(record.get("raw_alert"), dict) else record
    if not isinstance(raw, dict):
        return empty

    file_paths: set[str] = set()
    process_images: set[str] = set()
    target_process_images: set[str] = set()
    ip_addresses: set[str] = set()

    syscheck = raw.get("syscheck")
    if isinstance(syscheck, dict):
        _add_str(file_paths, syscheck.get("path"))

    data = raw.get("data")
    if isinstance(data, dict):
        _add_str(ip_addresses, data.get("srcip"))
        _add_str(ip_addresses, data.get("dstip"))

        win = data.get("win")
        if isinstance(win, dict):
            eventdata = win.get("eventdata")
            if isinstance(eventdata, dict):
                _add_str(file_paths, eventdata.get("targetFilename"))
                _add_str(process_images, eventdata.get("image"))
                _add_str(process_images, eventdata.get("sourceImage"))
                _add_str(target_process_images, eventdata.get("targetImage"))
                _add_str(ip_addresses, eventdata.get("sourceIp"))
                _add_str(ip_addresses, eventdata.get("destinationIp"))

    return {
        "file_paths": sorted(file_paths),
        "process_images": sorted(process_images),
        "target_process_images": sorted(target_process_images),
        "ip_addresses": sorted(ip_addresses),
    }
