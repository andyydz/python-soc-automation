import json
from pathlib import Path
from typing import Any

from soc_automation.integrity import calculate_sha256
from soc_automation.pipeline import process_wazuh_alert


def ingest_wazuh_alert_file(
    file_path: str | Path,
    include_sha256: bool = False,
) -> dict[str, Any]:
    """
    Read and process a Wazuh JSON alert file.

    Optionally calculates SHA-256 from the exact original
    file bytes before decoding or parsing the JSON.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be accessed.
        UnicodeDecodeError: If the file is not valid UTF-8.
        json.JSONDecodeError: If the file contains invalid JSON.
        ValueError: If the JSON root is not an object.
        TypeError: If include_sha256 is not a boolean.
    """

    # 1. Validate the SHA-256 option
    if not isinstance(include_sha256, bool):
        raise TypeError("include_sha256 must be a boolean.")

    # 2. Convert the supplied path into a Path object
    path = Path(file_path)

    # 3. Read the original file bytes once
    # Keep Python's original file exceptions unchanged.
    raw_bytes = path.read_bytes()

    # 4. Calculate SHA-256 from the exact original bytes
    sha256_hash = None

    if include_sha256:
        sha256_hash = calculate_sha256(raw_bytes)

    # 5. Decode the original bytes using UTF-8
    # UnicodeDecodeError is allowed to propagate.
    decoded_content = raw_bytes.decode("utf-8")

    # 6. Parse the JSON content
    # JSONDecodeError is allowed to propagate.
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
    )