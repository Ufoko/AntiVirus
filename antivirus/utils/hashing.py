from pathlib import Path
import hashlib
from typing import Tuple

BUF_SIZE = 65536  # 64 KiB chunks - optimal for most filesystems

def compute_hashes(file_path: str | Path) -> Tuple[str, str]:
    """
    Compute MD5 and SHA-256 hashes of a file.

    Returns:
        (md5_hex, sha256_hex) tuple
    """
    file_path = Path(file_path)
    
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    try:
        with file_path.open("rb") as f:
            while chunk := f.read(BUF_SIZE):
                md5.update(chunk)
                sha256.update(chunk)
    except PermissionError:
        raise PermissionError(f"Access denied: {file_path}")
    except Exception as e:
        raise RuntimeError(f"Failed to hash {file_path}: {e}") from e

    return md5.hexdigest(), sha256.hexdigest()


# Convenience functions for your signature detector
def get_sha256(file_path: str | Path) -> str:
    """Fast path when you only need SHA-256 (recommended for new AV)."""
    _, sha256 = compute_hashes(file_path)
    return sha256


def get_md5(file_path: str | Path) -> str:
    """Only use when you need legacy MD5 compatibility."""
    md5, _ = compute_hashes(file_path)
    return md5