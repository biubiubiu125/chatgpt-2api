"""OpenAI Sentinel Token (PoW) 生成与请求工具函数。

用于密码登录、注册等需要 sentinel token 的流程。
"""
from __future__ import annotations

import base64
import json
import random
import time
import uuid
from typing import TYPE_CHECKING

from services.browser_fingerprint import (
    CHROME146_ACCEPT_LANGUAGE,
    CHROME146_SEC_CH_UA,
    CHROME146_USER_AGENT,
    chrome146_headers,
)
from services.proxy_service import proxy_settings
from utils.turnstile import solve_turnstile_token

if TYPE_CHECKING:
    from curl_cffi.requests import Session


class SentinelTokenGenerator:
    """Sentinel Token 生成器（PoW - Proof of Work）。"""
    MAX_ATTEMPTS = 500_000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(self, device_id: str, ua: str):
        self.device_id = device_id
        self.user_agent = ua
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _get_config(self) -> list:
        perf_now = random.uniform(1000, 50000)
        return [
            "1920x1080",
            time.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)", time.gmtime()),
            4294705152,
            random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
            None,
            None,
            CHROME146_ACCEPT_LANGUAGE,
            random.random(),
            random.choice(["vendorSub-undefined", "plugins-undefined", "mimeTypes-undefined", "hardwareConcurrency-undefined"]),
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time.time() * 1000 - perf_now,
        ]

    @staticmethod
    def _b64(data) -> str:
        return base64.b64encode(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).decode("ascii")

    def generate_requirements_token(self) -> str:
        data = self._get_config()
        data[3] = 1
        data[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._b64(data)

    def generate_token(self, seed: str, difficulty: str) -> str:
        start = time.time()
        data = self._get_config()
        difficulty = str(difficulty or "0")
        for i in range(self.MAX_ATTEMPTS):
            data[3] = i
            data[9] = round((time.time() - start) * 1000)
            payload = self._b64(data)
            if self._fnv1a_32(seed + payload)[: len(difficulty)] <= difficulty:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))


# ── 默认 User-Agent 和 sec-ch-ua ──────────────────────────────
DEFAULT_SENTINEL_USER_AGENT = CHROME146_USER_AGENT
DEFAULT_SENTINEL_SEC_CH_UA = CHROME146_SEC_CH_UA


def _chrome146_user_agent(value: object = "") -> str:
    return DEFAULT_SENTINEL_USER_AGENT


def _chrome146_sec_ch_ua(value: object = "") -> str:
    return DEFAULT_SENTINEL_SEC_CH_UA


def sentinel_request_headers(user_agent: str, sec_ch_ua: str) -> dict[str, object]:
    """Headers for a same-origin Chrome 146 call to sentinel.openai.com."""

    return chrome146_headers({
        "Content-Type": "text/plain;charset=UTF-8",
        "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
        "Origin": "https://sentinel.openai.com",
        "User-Agent": user_agent,
        "sec-ch-ua": sec_ch_ua,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
    })


def build_sentinel_token(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    sec_ch_ua: str = "",
) -> tuple[str, str]:
    """请求 sentinel token 并返回 (sentinel_header_value, oai_sc_cookie_value)。

    Args:
        session: curl_cffi Session 实例
        device_id: 设备 ID
        flow: 流程标识（如 "password_verify", "username_password_create" 等）
        user_agent: 可选的 User-Agent 覆盖
        sec_ch_ua: 可选的 sec-ch-ua 覆盖

    Returns:
        (openai-sentinel-token header value, oai-sc cookie value) 元组

    Raises:
        RuntimeError: sentinel 请求失败
    """
    ua = _chrome146_user_agent(user_agent)
    ch_ua = _chrome146_sec_ch_ua(sec_ch_ua)
    generator = SentinelTokenGenerator(device_id, ua)
    requirements_token = generator.generate_requirements_token()
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        data=json.dumps({"p": requirements_token, "id": device_id, "flow": flow}),
        headers=sentinel_request_headers(ua, ch_ua),
        timeout=20,
        verify=not proxy_settings.should_skip_ssl_verify(),
    )

    try:
        data = resp.json() if resp.text else {}
    except Exception:
        fallback = json.dumps(
            {"p": generator.generate_requirements_token(), "t": "", "c": "", "id": device_id, "flow": flow},
            separators=(",", ":"),
        )
        return fallback, ""

    token = str(data.get("token") or "").strip()
    if resp.status_code != 200 or not token:
        raise RuntimeError(f"sentinel_req_failed_{resp.status_code}")
    pow_data = data.get("proofofwork") or {}
    p_value = (
        generator.generate_token(str(pow_data.get("seed") or ""), str(pow_data.get("difficulty") or "0"))
        if pow_data.get("required") and pow_data.get("seed")
        else generator.generate_requirements_token()
    )
    turnstile_data = data.get("turnstile") or {}
    so_token = ""
    if turnstile_data.get("required") and turnstile_data.get("dx"):
        # 对齐 sentinel sdk.js 的 token(flow) 行为：
        # t 字段由 req 阶段返回的 turnstile.dx 与本次 requirements_token 计算得到。
        so_token = solve_turnstile_token(str(turnstile_data.get("dx") or ""), requirements_token) or ""
        if not so_token:
            raise RuntimeError("sentinel_so_token_failed")
    sentinel_value = json.dumps({"p": p_value, "t": so_token, "c": token, "id": device_id, "flow": flow}, separators=(",", ":"))
    # oai-sc cookie = "0" + sentinel token "c" value (the challenge token from the server)
    oai_sc_value = "0" + token
    return sentinel_value, oai_sc_value


def build_sentinel_with_so_token(
    session: "Session",
    device_id: str,
    flow: str,
    *,
    user_agent: str = "",
    sec_ch_ua: str = "",
) -> tuple[str, str, str]:
    """请求 sentinel token 并返回 (sentinel_header_value, so_token_header_value, oai_sc_cookie_value)。

    Args:
        session: curl_cffi Session 实例
        device_id: 设备 ID
        flow: 流程标识（如 "oauth_create_account" 等）
        user_agent: 可选的 User-Agent 覆盖
        sec_ch_ua: 可选的 sec-ch-ua 覆盖

    Returns:
        (openai-sentinel-token, openai-sentinel-so-token, oai-sc cookie) 元组

    Raises:
        RuntimeError: sentinel 请求失败
    """
    ua = _chrome146_user_agent(user_agent)
    ch_ua = _chrome146_sec_ch_ua(sec_ch_ua)
    generator = SentinelTokenGenerator(device_id, ua)
    requirements_token = generator.generate_requirements_token()
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        data=json.dumps({"p": requirements_token, "id": device_id, "flow": flow}),
        headers=sentinel_request_headers(ua, ch_ua),
        timeout=20,
        verify=not proxy_settings.should_skip_ssl_verify(),
    )

    try:
        data = resp.json() if resp.text else {}
    except Exception:
        fallback = json.dumps(
            {"p": generator.generate_requirements_token(), "t": "", "c": "", "id": device_id, "flow": flow},
            separators=(",", ":"),
        )
        return fallback, "", ""

    token = str(data.get("token") or "").strip()
    if resp.status_code != 200 or not token:
        raise RuntimeError(f"sentinel_req_failed_{resp.status_code}")

    pow_data = data.get("proofofwork") or {}
    p_value = (
        generator.generate_token(str(pow_data.get("seed") or ""), str(pow_data.get("difficulty") or "0"))
        if pow_data.get("required") and pow_data.get("seed")
        else generator.generate_requirements_token()
    )

    turnstile_data = data.get("turnstile") or {}
    so_token = ""
    if turnstile_data.get("required") and turnstile_data.get("dx"):
        # 等待 5000ms 以模拟浏览器采集过程（对齐官方 SDK 行为）
        time.sleep(5.0)
        so_token = solve_turnstile_token(str(turnstile_data.get("dx") or ""), requirements_token) or ""
        if not so_token:
            raise RuntimeError("sentinel_so_token_failed")

    # Sentinel token 包含所有字段（向后兼容）
    sentinel_value = json.dumps({"p": p_value, "t": so_token, "c": token, "id": device_id, "flow": flow}, separators=(",", ":"))
    # oai-sc cookie = "0" + sentinel token "c" value
    oai_sc_value = "0" + token

    return sentinel_value, so_token, oai_sc_value
