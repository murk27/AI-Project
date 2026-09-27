"""mitmproxy addon: intercepts outbound POST requests, classifies the text
payload against the local classification engine, and blocks egress for
anything flagged 'Sensitive/Proprietary'.

Run as a regular (explicit) HTTP(S) proxy on port 8080:

    mitmdump -s proxy/addon.py --listen-port 8080

Client devices must be pointed at this host:8080 as their HTTP(S) proxy,
and must trust mitmproxy's CA (~/.mitmproxy/mitmproxy-ca-cert.pem) to allow
TLS interception. See README.md for setup notes and caveats (e.g. devices
that pin certificates, or that can't be configured to use a proxy/CA at
all, cannot be inspected this way).
"""

from __future__ import annotations

import datetime as dt

import httpx
from mitmproxy import ctx, http

from proxy.config import CLASSIFY_TIMEOUT_SECONDS, CLASSIFY_URL, FAIL_OPEN, load_device_map
from proxy.db import init_db, log_event
from proxy.extract import extract_text


class ShadowAIGuard:
    def __init__(self) -> None:
        self._client: httpx.AsyncClient | None = None
        self._device_map: dict = {}

    def load(self, loader) -> None:
        init_db()
        self._device_map = load_device_map()

    def running(self) -> None:
        self._client = httpx.AsyncClient(timeout=CLASSIFY_TIMEOUT_SECONDS)

    async def done(self) -> None:
        if self._client is not None:
            await self._client.aclose()

    def _device_info(self, source_ip: str) -> tuple[str | None, str | None]:
        entry = self._device_map.get(source_ip)
        if entry:
            return entry.get("label"), entry.get("type")
        return None, "unknown"

    async def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method != "POST" or not flow.request.content:
            return

        source_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "unknown"
        device_label, device_type = self._device_info(source_ip)
        destination_url = flow.request.pretty_url
        timestamp = dt.datetime.now(dt.timezone.utc).isoformat()

        text = extract_text(flow.request.headers.get("content-type"), flow.request.content)
        if not text.strip():
            log_event(
                timestamp=timestamp,
                source_ip=source_ip,
                device_label=device_label,
                device_type=device_type,
                destination_url=destination_url,
                method=flow.request.method,
                action="allowed",
                classification=None,
                confidence_score=None,
                entity_type=None,
                flagged_content=None,
            )
            return

        try:
            resp = await self._client.post(CLASSIFY_URL, json={"source_ip": source_ip, "text_content": text})
            resp.raise_for_status()
            result = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            ctx.log.warn(f"classify request failed ({exc}); fail_open={FAIL_OPEN}")
            log_event(
                timestamp=timestamp,
                source_ip=source_ip,
                device_label=device_label,
                device_type=device_type,
                destination_url=destination_url,
                method=flow.request.method,
                action="allowed" if FAIL_OPEN else "blocked",
                classification="ERROR",
                confidence_score=None,
                entity_type=None,
                flagged_content=None,
            )
            if not FAIL_OPEN:
                flow.response = http.Response.make(
                    502, b'{"error": "classification engine unavailable"}', {"Content-Type": "application/json"}
                )
            return

        classification = result.get("classification", "Safe")
        is_sensitive = classification == "Sensitive/Proprietary"

        log_event(
            timestamp=timestamp,
            source_ip=source_ip,
            device_label=device_label,
            device_type=device_type,
            destination_url=destination_url,
            method=flow.request.method,
            action="blocked" if is_sensitive else "allowed",
            classification=classification,
            confidence_score=result.get("confidence_score"),
            entity_type=result.get("entity_type"),
            flagged_content=result.get("trigger"),
        )

        if is_sensitive:
            ctx.log.info(f"BLOCKED egress from {source_ip} to {destination_url}: {result.get('entity_type')}")
            flow.response = http.Response.make(
                403,
                b'{"error": "Blocked by DSPM egress guard: sensitive/proprietary content detected"}',
                {"Content-Type": "application/json"},
            )


addons = [ShadowAIGuard()]
