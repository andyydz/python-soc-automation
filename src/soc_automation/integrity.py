import hashlib


def calculate_sha256(data: bytes) -> str:
    """
    Calculate the SHA-256 hash of original file bytes.
    """

    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes.")

    return hashlib.sha256(data).hexdigest()