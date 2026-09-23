from __future__ import annotations

from collections.abc import Iterable, Mapping


ALLOWED_MAIL_PROVIDER_TYPES = frozenset(
    {"yyds_mail", "remail", "outlook_token", "icloud_api"}
)
COMMON_PROVIDER_KEYS = frozenset({"id", "provider_id", "provider_ref", "enable", "type", "label"})
PROVIDER_KEYS_BY_TYPE = {
    "yyds_mail": frozenset({"api_base", "api_key", "domain", "subdomain", "wildcard"}),
    "remail": frozenset({"api_base", "api_key", "service_mode", "supply", "project_id", "product_id", "email_suffix"}),
    "outlook_token": frozenset({"mailboxes", "mode", "imap_host", "message_limit", "alias_enabled", "alias_per_email", "alias_prefix", "alias_include_original"}),
    "icloud_api": frozenset({"api_base", "api_key"}),
}


def validate_provider_type(value: object) -> str:
    provider_type = str(value or "").strip().lower()
    if provider_type not in ALLOWED_MAIL_PROVIDER_TYPES:
        allowed = ", ".join(sorted(ALLOWED_MAIL_PROVIDER_TYPES))
        raise ValueError(f"不支持的 mail.provider: {provider_type or '<empty>'}；仅支持 {allowed}")
    return provider_type


def _sanitize_provider_entry(item: Mapping[str, object]) -> dict:
    provider_type = validate_provider_type(item.get("type"))
    allowed_keys = COMMON_PROVIDER_KEYS | PROVIDER_KEYS_BY_TYPE[provider_type]
    entry = {str(key): value for key, value in item.items() if str(key) in allowed_keys}
    entry["type"] = provider_type
    if "id" in entry:
        entry["id"] = str(entry["id"]).strip()
    if "provider_id" in entry:
        entry["provider_id"] = str(entry["provider_id"]).strip()
    if "provider_ref" in entry:
        entry["provider_ref"] = str(entry["provider_ref"]).strip()
    if "label" in entry:
        entry["label"] = str(entry["label"]).strip()
    return entry


def validate_provider_entries(value: object) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        raise ValueError("mail.providers must be a list")
    result: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("mail.providers entries must be objects")
        result.append(_sanitize_provider_entry(item))
    return result


def sanitize_legacy_provider_entries(value: object) -> list[dict]:
    """Keep only the four supported providers while importing old state.

    Runtime configuration updates still use ``validate_provider_entries`` and
    reject unsupported providers.  This helper is intentionally permissive so
    an old register.json or database row cannot prevent the application from
    starting.
    """
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        return []
    result: list[dict] = []
    for item in value:
        if not isinstance(item, Mapping):
            continue
        provider_type = str(item.get("type") or "").strip().lower()
        if provider_type not in ALLOWED_MAIL_PROVIDER_TYPES:
            continue
        result.append(_sanitize_provider_entry({**item, "type": provider_type}))
    return result
