import json
from pathlib import Path
from typing import Any

from soc_automation.integrity import calculate_sha256
from soc_automation.pipeline import process_wazuh_alert


def ingest_wazuh_alert_file(
    file_path: str | Path,
    include_sha256: bool = False,
    include_enrichment: bool = False,
) -> dict[str, Any]:
    """
    Read and process a Wazuh JSON alert file.

    Optionally calculates SHA-256 from the exact original
    file bytes before decoding or parsing the JSON.

    Supports UTF-8 files with or without a BOM.

    Optionally enables alert enrichment during processing.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be accessed.
        UnicodeDecodeError: If the file is not valid UTF-8.
        json.JSONDecodeError: If the file contains invalid JSON.
        ValueError: If the JSON root is not an object.
        TypeError: If an option has an invalid type.
    """

    # 1. Validate options
    if not isinstance(include_sha256, bool):
        raise TypeError("include_sha256 must be a boolean.")

    if not isinstance(include_enrichment, bool):
        raise TypeError("include_enrichment must be a boolean.")

    # 2. Convert the supplied path into a Path object
    path = Path(file_path)

    # 3. Read the original file bytes once
    raw_bytes = path.read_bytes()

    # 4. Calculate SHA-256 from the exact original bytes
    sha256_hash = None

    if include_sha256:
        sha256_hash = calculate_sha256(raw_bytes)

    # 5. Decode using UTF-8 with BOM support
    decoded_content = raw_bytes.decode("utf-8-sig")

    # 6. Parse the JSON content
    alert = json.loads(decoded_content)

    # 7. Validate the JSON root structure
    if not isinstance(alert, dict):
        raise ValueError(
            "Wazuh alert JSON must contain an object."
        )

    # 8. Process the validated alert
    return process_wazuh_alert(
        alert,
        sha256_hash=sha256_hash,
        include_enrichment=include_enrichment,
    )