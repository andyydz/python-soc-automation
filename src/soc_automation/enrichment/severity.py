def get_severity_context(level: int) -> dict:
    """
    Convert a Wazuh numeric severity level
    into a human-readable context label.

    The original numeric level is preserved.
    """

    if isinstance(level, bool) or not isinstance(level, int):
        raise TypeError("Severity level must be an integer.")

    if not 0 <= level <= 15:
        raise ValueError("Severity level must be between 0 and 15.")

    if level == 0:
        label = "Ignored"
    elif level <= 4:
        label = "Low"
    elif level <= 7:
        label = "Medium"
    elif level <= 11:
        label = "High"
    else:
        label = "Critical"

    return {
        "original_level": level,
        "severity_label": label,
        "classification_source": "python_soc_automation"
    }