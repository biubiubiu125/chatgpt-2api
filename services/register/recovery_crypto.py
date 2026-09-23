from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from typing import Any, Callable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


_FORMAT_PREFIX = b"CHATGPT-2API-REGISTER-RECOVERY-V1\n"
_ASSOCIATED_DATA = b"chatgpt-2api/register-core-results"


class SecureRecoveryFileError(RuntimeError):
    pass


def _key() -> bytes:
    secret = str(
        os.getenv("CHATGPT2API_REGISTER_RECOVERY_KEY")
        or os.getenv("CHATGPT2API_AUTH_KEY")
        or ""
    ).strip()
    if not secret:
        try:
            from services.config import config

            secret = str(config.auth_key or "").strip()
        except Exception:
            secret = ""
    if not secret:
        raise RuntimeError("register recovery encryption key is not configured")
    return hashlib.sha256(
        b"chatgpt-2api/register-recovery/aes-gcm/v1\0" + secret.encode("utf-8")
    ).digest()


def _harden_file(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    if os.name != "nt":
        return
    username = str(os.getenv("USERNAME") or "").strip()
    if not username:
        return
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{username}:F"],
            check=False,
            capture_output=True,
            text=True,
        )
    except (OSError, ValueError):
        pass


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        os.replace(temporary_path, path)
        temporary_path = None
        _harden_file(path)
    finally:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def _encode(data: Any) -> bytes:
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(12)
    ciphertext = AESGCM(_key()).encrypt(nonce, payload, _ASSOCIATED_DATA)
    encoded = base64.urlsafe_b64encode(nonce + ciphertext)
    return _FORMAT_PREFIX + encoded + b"\n"


def _decode(raw: bytes) -> Any:
    if not raw.startswith(_FORMAT_PREFIX):
        return json.loads(raw.decode("utf-8"))
    encoded = raw[len(_FORMAT_PREFIX):].strip()
    encrypted = base64.urlsafe_b64decode(encoded)
    if len(encrypted) <= 12:
        raise ValueError("register recovery payload is truncated")
    nonce, ciphertext = encrypted[:12], encrypted[12:]
    payload = AESGCM(_key()).decrypt(nonce, ciphertext, _ASSOCIATED_DATA)
    return json.loads(payload.decode("utf-8"))


def read_secure_json_file(
    path: Path,
    *,
    default_factory: Callable[[], Any] = dict,
    expected_types: type | tuple[type, ...] | None = None,
) -> Any:
    candidates = (path, path.with_suffix(path.suffix + ".bak"))
    encrypted_seen = False
    decrypt_error: Exception | None = None
    for candidate in candidates:
        if not candidate.exists() or candidate.is_dir():
            continue
        raw = candidate.read_bytes()
        if raw.startswith(_FORMAT_PREFIX):
            encrypted_seen = True
        try:
            data = _decode(raw)
        except Exception as exc:
            if raw.startswith(_FORMAT_PREFIX):
                decrypt_error = exc
            continue
        if expected_types is not None and not isinstance(data, expected_types):
            continue
        if candidate != path:
            try:
                write_secure_json_file(path, data)
            except Exception:
                pass
        elif not candidate.read_bytes().startswith(_FORMAT_PREFIX):
            try:
                write_secure_json_file(path, data)
            except Exception:
                pass
        return data
    if encrypted_seen:
        raise SecureRecoveryFileError(
            "register recovery file cannot be decrypted with the configured key"
        ) from decrypt_error
    return default_factory()


def write_secure_json_file(path: Path, data: Any, *, backup: bool = True) -> None:
    content = _encode(data)
    _atomic_write(path, content)
    if backup:
        _atomic_write(path.with_suffix(path.suffix + ".bak"), content)
