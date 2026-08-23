#!/usr/bin/env python3
"""Nosh managed mitmproxy evidence and content gate addon.

The addon never writes raw request headers, credentials, cookies, or query
values to its NDJSON output. Exact request targets remain bound by SHA-256.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, urljoin, urlsplit

try:
    from mitmproxy import ctx, http
except ImportError:  # Allows the sanitizer self-test without mitmproxy installed.
    ctx = None
    http = None


API_VERSION = "notty.dev/v1alpha1"
SCHEMA_VERSION = 1
ALLOWED_MODES = {"observe", "offline-replay", "live-buffer-verify"}
SAFE_REPRESENTATION_HEADERS = {
    "accept",
    "accept-encoding",
    "accept-language",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-range",
    "if-unmodified-since",
    "range",
}
CREDENTIAL_HEADERS = {"authorization", "cookie", "proxy-authorization"}
CREDENTIAL_HEADER_NAME = re.compile(
    r"(?:^|[-_])(?:api[-_]?key|auth(?:orization)?|credential|cookie|pass(?:word)?|private[-_]?token|secret|session|signature|token)(?:$|[-_])",
    re.IGNORECASE,
)
PRIVATE_RESPONSE_HEADERS = {"proxy-authenticate", "set-cookie", "www-authenticate"}
SECRET_QUERY_KEY = re.compile(
    r"(?:auth|code|credential|key|pass|password|secret|session|signature|sig|token)",
    re.IGNORECASE,
)
SECRET_PATH_SEGMENT = re.compile(
    r"^(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9_-]{48,}|eyJ[A-Za-z0-9_-]{16,})$"
)
DIGEST = re.compile(r"^sha256:[a-f0-9]{64}$")
RUN_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
PINNED_IMAGE_DIGEST = (
    "sha256:00b77b5d8804c8ad18cb6caefbf9d5849e895e8986c5ce011f4ae30f4385962f"
)
MANIFEST_MAX_BYTES = 16 * 1024 * 1024
EVIDENCE_MAX_BYTES = 128 * 1024 * 1024
EVIDENCE_STATS_RESERVE = 64 * 1024
EVIDENCE_MAX_RECORDS = 1_000_000
EVIDENCE_MAX_LINE_BYTES = 1024 * 1024


def stable_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def sha256(value: bytes | str) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def observed_at(timestamp: float | None = None) -> str:
    selected = datetime.fromtimestamp(
        timestamp if timestamp is not None else datetime.now().timestamp(),
        tz=timezone.utc,
    )
    return selected.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} is not a timestamp")
    try:
        selected = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{label} is not a timestamp") from error
    if selected.tzinfo is None:
        raise ValueError(f"{label} must include a timezone")
    normalized = selected.astimezone(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")
    if normalized != value:
        raise ValueError(f"{label} is not canonical")
    return normalized


def normalized_host(value: str) -> str:
    host = value.strip().lower().strip("[]")
    if not host or len(host) > 253:
        raise ValueError("HTTP hostname is empty or too long")
    try:
        selected = host.encode("idna").decode("ascii")
        try:
            return ipaddress.ip_address(selected).compressed.lower()
        except ValueError:
            pass
        if any(
            not label
            or len(label) > 63
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in selected.split(".")
        ):
            raise ValueError("HTTP hostname labels are invalid")
        return selected
    except UnicodeError as error:
        raise ValueError("HTTP hostname is not valid IDNA") from error


def connection_endpoint(value: Any, label: str) -> tuple[str, int]:
    if not isinstance(value, tuple) or len(value) < 2:
        raise ValueError(f"{label} is unavailable")
    try:
        address = ipaddress.ip_address(str(value[0]).split("%", 1)[0]).compressed.lower()
        port = int(value[1])
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} is invalid") from error
    if port < 1 or port > 65535:
        raise ValueError(f"{label} port is invalid")
    return address, port


def display_url(raw_url: str) -> tuple[str, str, str, int]:
    parsed = urlsplit(raw_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError(f"unsupported HTTP scheme: {scheme}")
    host = normalized_host(parsed.hostname or "")
    port = parsed.port or (443 if scheme == "https" else 80)
    path_segments = [
        "<redacted>" if SECRET_PATH_SEGMENT.fullmatch(segment) else segment
        for segment in (parsed.path or "/").split("/")
    ]
    query_parts: list[str] = []
    for index, (name, _value) in enumerate(parse_qsl(parsed.query, keep_blank_values=True)):
        if index >= 128:
            query_parts.append("truncated=<redacted>")
            break
        display_name = "<redacted-key>" if (
            len(name) > 128 or SECRET_QUERY_KEY.search(name)
        ) else name
        query_parts.append(f"{quote(display_name, safe='')}=<redacted>")
    default_port = (scheme == "https" and port == 443) or (
        scheme == "http" and port == 80
    )
    display_host = f"[{host}]" if ":" in host else host
    authority = display_host if default_port else f"{display_host}:{port}"
    rendered = f"{scheme}://{authority}{'/'.join(path_segments)}"
    if query_parts:
        rendered = f"{rendered}?{'&'.join(query_parts)}"
    if len(rendered) > 8192:
        raise ValueError("sanitized HTTP URL exceeds its display limit")
    return rendered, scheme, host, port


def normalized_headers(headers: Any) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for name, value in headers.items(multi=True):
        lowered = str(name).strip().lower()
        selected = str(value)
        if "\r" in selected or "\n" in selected or len(selected) > 65536:
            raise ValueError(f"invalid HTTP header: {lowered}")
        values.append((lowered, selected))
    return values


def representation_digest(headers: Any) -> str:
    selected = sorted(
        entry for entry in normalized_headers(headers)
        if entry[0] in SAFE_REPRESENTATION_HEADERS
    )
    return sha256(stable_json(selected))


def response_headers_digest(headers: Any) -> str:
    selected = sorted(
        entry for entry in normalized_headers(headers)
        if entry[0] not in PRIVATE_RESPONSE_HEADERS
    )
    return sha256(stable_json(selected))


def request_identity(request_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "method": request_record["method"],
        "scheme": request_record["scheme"],
        "hostname": request_record["hostname"],
        "port": request_record["port"],
        "requestTargetDigest": request_record["requestTargetDigest"],
        "requestBodyDigest": request_record["requestBodyDigest"],
        "representationHeadersDigest": request_record["representationHeadersDigest"],
        "credentialed": request_record["credentialed"],
    }


class NoshHttpEvidence:
    def __init__(self) -> None:
        self.run_id = ""
        self.run_root: Path | None = None
        self.mode = ""
        self.evidence_path: Path | None = None
        self.cas_root: Path | None = None
        self.manifest: dict[str, Any] | None = None
        self.maximum_body_bytes = 512 * 1024 * 1024
        self.maximum_cas_bytes = 8 * 1024 * 1024 * 1024
        self.maximum_cas_objects = 10_000
        self.cas_bytes = 0
        self.cas_objects: set[str] = set()
        self.entries: dict[str, dict[str, Any]] = {}
        self.capture_entries: dict[str, dict[str, Any]] = {}
        self.ambiguous_request_keys: set[str] = set()
        self.content_assurance_gaps: set[str] = set()
        self.content_manifest_digest: str | None = None
        self.collector_image_digest: str | None = None
        self.collector_addon_digest: str | None = None
        self.collector_wrapper_digest: str | None = None
        self.evidence_handle: Any = None
        self.stats_emitted = False
        self.incomplete_response_records = 0
        self.evidence_bytes = 0
        self.evidence_records = 0
        self.maximum_evidence_bytes = EVIDENCE_MAX_BYTES
        self.evidence_stats_reserve = EVIDENCE_STATS_RESERVE
        self.maximum_evidence_records = EVIDENCE_MAX_RECORDS
        self.counts = {
            "requests": 0,
            "responses": 0,
            "redirects": 0,
            "errors": 0,
            "opaqueConnects": 0,
            "incompleteBodies": 0,
            "droppedRecords": 0,
            "reviewOnlyRecords": 0,
        }
        self.coverage_gaps: set[str] = set()

    def load(self, _loader: Any) -> None:
        try:
            if ctx is None or http is None:
                raise RuntimeError("mitmproxy Python modules are unavailable")
            self.run_id = os.environ.get("NOSH_HTTP_RUN_ID", "")
            if not RUN_ID.fullmatch(self.run_id):
                raise ValueError("NOSH_HTTP_RUN_ID is missing or invalid")
            self.mode = os.environ.get("NOSH_HTTP_CAPTURE_MODE", "")
            if self.mode not in ALLOWED_MODES:
                raise ValueError("NOSH_HTTP_CAPTURE_MODE is invalid")
            self.run_root = self._absolute_env_path("NOSH_HTTP_RUN_ROOT")
            self._trusted_directory(self.run_root, "HTTP private run root")
            self.evidence_path = self._run_child_env_path("NOSH_HTTP_EVIDENCE_PATH")
            self.cas_root = self._run_child_env_path("NOSH_HTTP_CAS_ROOT")
            maximum_body_bytes = os.environ.get(
                "NOSH_HTTP_MAX_BODY_BYTES",
                str(512 * 1024 * 1024),
            )
            if (
                not maximum_body_bytes.isdecimal()
                or int(maximum_body_bytes) < 1
                or int(maximum_body_bytes) > 512 * 1024 * 1024
            ):
                raise ValueError(
                    "NOSH_HTTP_MAX_BODY_BYTES must be from 1 to 536870912"
                )
            self.maximum_body_bytes = int(maximum_body_bytes)
            maximum_cas_bytes = os.environ.get(
                "NOSH_HTTP_MAX_CAS_BYTES", str(8 * 1024 * 1024 * 1024)
            )
            maximum_cas_objects = os.environ.get(
                "NOSH_HTTP_MAX_CAS_OBJECTS", "10000"
            )
            if (
                not maximum_cas_bytes.isdecimal()
                or not 1 <= int(maximum_cas_bytes) <= 8 * 1024 * 1024 * 1024
                or not maximum_cas_objects.isdecimal()
                or not 1 <= int(maximum_cas_objects) <= 10_000
            ):
                raise ValueError("HTTP CAS run quota is invalid")
            self.maximum_cas_bytes = int(maximum_cas_bytes)
            self.maximum_cas_objects = int(maximum_cas_objects)
            self.collector_image_digest = self._digest_env(
                "NOSH_HTTP_COLLECTOR_IMAGE_DIGEST"
            )
            self.collector_addon_digest = self._digest_env(
                "NOSH_HTTP_COLLECTOR_ADDON_DIGEST"
            )
            self.collector_wrapper_digest = self._digest_env(
                "NOSH_HTTP_COLLECTOR_WRAPPER_DIGEST"
            )
            if self.collector_image_digest != PINNED_IMAGE_DIGEST:
                raise ValueError("managed HTTP collector image digest is not pinned")
            self._open_evidence()
            self._initialize_cas()
            if self.mode != "observe":
                manifest_path = self._run_child_env_path("NOSH_HTTP_CONTENT_MANIFEST")
                self.manifest = self._load_manifest(manifest_path)
                if self.manifest.get("mode") != self.mode:
                    raise ValueError("HTTP content manifest mode does not match capture mode")
                self.content_manifest_digest = self.manifest["contentHash"]
                self.entries = {
                    entry["requestKey"]: entry for entry in self.manifest["entries"]
                }
        except Exception as error:
            self._fatal(None, f"HTTP capture initialization failed: {error}")

    @staticmethod
    def _absolute_env_path(name: str) -> Path:
        value = os.environ.get(name, "")
        if not value or not os.path.isabs(value):
            raise ValueError(f"{name} must be an absolute path")
        return Path(value)

    @staticmethod
    def _digest_env(name: str) -> str:
        value = os.environ.get(name, "")
        if not DIGEST.fullmatch(value):
            raise ValueError(f"{name} must be an exact SHA-256 digest")
        return value

    def _run_child_env_path(self, name: str) -> Path:
        selected = self._absolute_env_path(name).absolute()
        assert self.run_root is not None
        root = self.run_root.absolute()
        if selected == root or not selected.is_relative_to(root):
            raise ValueError(f"{name} escapes NOSH_HTTP_RUN_ROOT")
        return selected

    def _open_evidence(self) -> None:
        assert self.evidence_path is not None
        self.evidence_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._trusted_directory(self.evidence_path.parent, "HTTP evidence parent")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.evidence_path, flags, 0o600)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            os.close(descriptor)
            raise ValueError("HTTP evidence path is not a singly-linked regular file")
        if details.st_uid != os.geteuid():
            os.close(descriptor)
            raise ValueError("HTTP evidence path has an unexpected owner")
        os.fchmod(descriptor, 0o600)
        self.evidence_handle = os.fdopen(descriptor, "w", encoding="utf-8", buffering=1)

    @staticmethod
    def _trusted_directory(directory: Path, label: str) -> None:
        if directory.resolve() != directory.absolute():
            raise ValueError(f"{label} contains a symlink")
        details = directory.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.geteuid()
            or stat.S_IMODE(details.st_mode) != 0o700
        ):
            raise ValueError(f"{label} is unsafe")

    def _initialize_cas(self) -> None:
        assert self.cas_root is not None
        for directory in (
            self.cas_root,
            self.cas_root / "objects",
            self.cas_root / "objects" / "sha256",
            self.cas_root / "tmp",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._trusted_directory(directory, f"HTTP CAS directory {directory}")
        assert self.cas_root is not None
        objects_root = self.cas_root / "objects" / "sha256"
        for shard in objects_root.iterdir():
            self._trusted_directory(shard, f"HTTP CAS shard {shard}")
            if not re.fullmatch(r"[a-f0-9]{2}", shard.name):
                raise ValueError("HTTP CAS shard name is invalid")
            for selected in shard.iterdir():
                details = selected.lstat()
                if (
                    not re.fullmatch(r"[a-f0-9]{64}", selected.name)
                    or not stat.S_ISREG(details.st_mode)
                    or stat.S_ISLNK(details.st_mode)
                    or details.st_nlink != 1
                    or details.st_uid != os.geteuid()
                    or stat.S_IMODE(details.st_mode) != 0o400
                ):
                    raise ValueError("HTTP CAS object is unsafe")
                self.cas_objects.add(selected.name)
                self.cas_bytes += details.st_size
                if (
                    len(self.cas_objects) > self.maximum_cas_objects
                    or self.cas_bytes > self.maximum_cas_bytes
                ):
                    raise ValueError("HTTP CAS exceeds its configured run quota")

    def _load_manifest(self, manifest_path: Path) -> dict[str, Any]:
        self._trusted_directory(manifest_path.parent, "HTTP content manifest parent")
        descriptor = os.open(
            manifest_path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise ValueError("HTTP content manifest is not a regular private file")
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o400:
                raise ValueError("HTTP content manifest owner or mode is invalid")
            if details.st_size > 16 * 1024 * 1024:
                raise ValueError("HTTP content manifest exceeds its byte limit")
            chunks: list[bytes] = []
            remaining = details.st_size
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            document = json.loads(b"".join(chunks).decode("utf-8"))
        finally:
            os.close(descriptor)
        if (
            set(document) != {
                "schemaVersion", "apiVersion", "kind", "generatedAt", "runId",
                "mode", "entries", "contentHash",
            }
            or document.get("schemaVersion") != 1
            or document.get("apiVersion") != API_VERSION
            or document.get("kind") != "NoshHttpContentManifest"
            or not RUN_ID.fullmatch(str(document.get("runId", "")))
            or canonical_timestamp(
                document.get("generatedAt"), "HTTP content manifest generatedAt"
            ) != document.get("generatedAt")
            or not DIGEST.fullmatch(str(document.get("contentHash", "")))
            or not isinstance(document.get("entries"), list)
            or not 1 <= len(document.get("entries", [])) <= 100_000
        ):
            raise ValueError("HTTP content manifest contract is invalid")
        base = {key: value for key, value in document.items() if key != "contentHash"}
        if sha256(stable_json(base)) != document["contentHash"]:
            raise ValueError("HTTP content manifest hash is invalid")
        request_keys: set[str] = set()
        for entry in document["entries"]:
            if not isinstance(entry, dict) or set(entry) != {
                "requestKey", "request", "response", "sourceExchangeId", "capturedAt",
            }:
                raise ValueError("HTTP content manifest entry fields are invalid")
            request = entry.get("request")
            response = entry.get("response")
            if not isinstance(request, dict) or set(request) != {
                "method", "scheme", "hostname", "port", "requestTargetDigest",
                "requestBodyDigest", "representationHeadersDigest", "credentialed",
            }:
                raise ValueError("HTTP content manifest request fields are invalid")
            if not isinstance(response, dict) or set(response) != {
                "status", "bodyDigest", "bodyBytes", "contentType", "contentEncoding",
                "location", "locationDigest",
            }:
                raise ValueError("HTTP content manifest response fields are invalid")
            request_key = entry.get("requestKey")
            if (
                not DIGEST.fullmatch(str(request_key or ""))
                or request_key in request_keys
                or request_key != sha256(stable_json(request))
            ):
                raise ValueError("HTTP content manifest request key is invalid")
            request_keys.add(request_key)
            if (
                not re.fullmatch(r"[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}", request.get("method", ""))
                or request.get("method") == "HEAD"
                or request.get("scheme") not in {"http", "https"}
                or normalized_host(str(request.get("hostname", ""))) != request.get("hostname")
                or isinstance(request.get("port"), bool)
                or not isinstance(request.get("port"), int)
                or not 1 <= request["port"] <= 65_535
                or not DIGEST.fullmatch(str(request.get("requestTargetDigest", "")))
                or (
                    request.get("requestBodyDigest") is not None
                    and not DIGEST.fullmatch(str(request.get("requestBodyDigest")))
                )
                or not DIGEST.fullmatch(str(request.get("representationHeadersDigest", "")))
                or request.get("credentialed") is not False
            ):
                raise ValueError("HTTP content manifest request identity is invalid")
            status_code = response.get("status")
            body_bytes = response.get("bodyBytes")
            if (
                isinstance(status_code, bool)
                or not isinstance(status_code, int)
                or not 200 <= status_code <= 599
                or status_code in {206, 304}
                or not DIGEST.fullmatch(str(response.get("bodyDigest", "")))
                or isinstance(body_bytes, bool)
                or not isinstance(body_bytes, int)
                or not 0 <= body_bytes <= self.maximum_body_bytes
            ):
                raise ValueError("HTTP content manifest body digest is invalid")
            for name, maximum in (("contentType", 1024), ("contentEncoding", 128)):
                value = response.get(name)
                if value is not None and (
                    not isinstance(value, str)
                    or not value
                    or len(value) > maximum
                    or "\r" in value
                    or "\n" in value
                ):
                    raise ValueError(f"HTTP content manifest {name} is invalid")
            location = response.get("location")
            location_digest = response.get("locationDigest")
            if (
                (location is None) != (location_digest is None)
                or (
                    location is not None
                    and (
                        not isinstance(location, str)
                        or not location
                        or len(location) > 65_536
                        or "\r" in location
                        or "\n" in location
                        or not 300 <= status_code <= 399
                        or status_code == 304
                        or sha256(location) != location_digest
                    )
                )
                or not DIGEST.fullmatch(str(entry.get("sourceExchangeId", "")))
                or canonical_timestamp(
                    entry.get("capturedAt"), "HTTP content manifest capturedAt"
                ) != entry.get("capturedAt")
            ):
                raise ValueError("HTTP content manifest response binding is invalid")
        return document

    def _common(self, kind: str, timestamp: float | None = None) -> dict[str, Any]:
        return {
            "schemaVersion": SCHEMA_VERSION,
            "apiVersion": API_VERSION,
            "recordKind": kind,
            "runId": self.run_id,
            "observedAt": observed_at(timestamp),
            "provider": "mitmproxy",
            "captureAuthority": "managed",
            "captureMode": "managed-proxy",
        }

    def _emit(self, record: dict[str, Any], *, terminal: bool = False) -> None:
        if self.evidence_handle is None:
            raise RuntimeError("HTTP evidence output is unavailable")
        payload = f"{stable_json(record)}\n"
        payload_bytes = len(payload.encode("utf-8"))
        byte_limit = self.maximum_evidence_bytes if terminal else (
            self.maximum_evidence_bytes - self.evidence_stats_reserve
        )
        record_limit = self.maximum_evidence_records if terminal else (
            self.maximum_evidence_records - 1
        )
        if (
            payload_bytes > EVIDENCE_MAX_LINE_BYTES
            or self.evidence_bytes + payload_bytes > byte_limit
            or self.evidence_records >= record_limit
        ):
            if not terminal:
                self.counts["droppedRecords"] += 1
                self.coverage_gaps.update({"dropped-records", "provider-loss"})
            raise RuntimeError("HTTP evidence output reached its bounded limit")
        self.evidence_handle.write(payload)
        self.evidence_handle.flush()
        self.evidence_bytes += payload_bytes
        self.evidence_records += 1

    def _exchange_id(self, flow: Any) -> str:
        return sha256(stable_json([self.run_id, str(flow.id)]))

    def _request_record(self, flow: Any) -> dict[str, Any]:
        request = flow.request
        rendered, scheme, hostname, port = display_url(request.pretty_url)
        raw_body = request.raw_content
        path_value = request.path or "/"
        headers = normalized_headers(request.headers)
        client_address, client_port = connection_endpoint(
            flow.client_conn.peername,
            "downstream client endpoint",
        )
        proxy_address, proxy_port = connection_endpoint(
            flow.client_conn.sockname,
            "proxy listener endpoint",
        )
        record = {
            **self._common("http-request", request.timestamp_start),
            "exchangeId": self._exchange_id(flow),
            "method": request.method.upper(),
            "scheme": scheme,
            "hostname": hostname,
            "port": port,
            "displayUrl": rendered,
            "requestTargetDigest": sha256(path_value),
            "requestBodyDigest": sha256(raw_body) if raw_body is not None else None,
            "requestBodyBytes": len(raw_body) if raw_body is not None else None,
            "representationHeadersDigest": representation_digest(request.headers),
            "credentialed": (
                bool(urlsplit(request.pretty_url).username)
                or bool(urlsplit(request.pretty_url).password)
                or any(
                    (name in CREDENTIAL_HEADERS or CREDENTIAL_HEADER_NAME.search(name))
                    and bool(value)
                    for name, value in headers
                )
            ),
            "tlsInterception": "intercepted" if scheme == "https" else "plaintext",
            "upstreamTlsVerified": None,
            "clientAddress": client_address,
            "clientPort": client_port,
            "proxyAddress": proxy_address,
            "proxyPort": proxy_port,
        }
        return record

    @staticmethod
    def _request_key(record: dict[str, Any]) -> str:
        return sha256(stable_json(request_identity(record)))

    @staticmethod
    def _response_from_entry(entry: dict[str, Any], body: bytes) -> Any:
        response = entry["response"]
        headers: dict[str, str] = {}
        if response.get("contentType"):
            headers["Content-Type"] = response["contentType"]
        if response.get("location"):
            headers["Location"] = response["location"]
        rebuilt = http.Response.make(response["status"], b"", headers)
        rebuilt.raw_content = body
        if response.get("contentEncoding"):
            rebuilt.headers["Content-Encoding"] = response["contentEncoding"]
        rebuilt.headers["Content-Length"] = str(len(body))
        return rebuilt

    def _add_capture_entry(
        self,
        request_record: dict[str, Any],
        response: Any,
        raw_body: bytes,
    ) -> None:
        request_key = self._request_key(request_record)
        if request_key in self.ambiguous_request_keys:
            return
        location = None
        if 300 <= response.status_code <= 399 and response.status_code != 304:
            location = response.headers.get("location") or None
        entry = {
            "requestKey": request_key,
            "request": request_identity(request_record),
            "response": {
                "status": response.status_code,
                "bodyDigest": sha256(raw_body),
                "bodyBytes": len(raw_body),
                "contentType": response.headers.get("content-type") or None,
                "contentEncoding": response.headers.get("content-encoding") or None,
                "location": location,
                "locationDigest": sha256(location) if location is not None else None,
            },
            "sourceExchangeId": request_record["exchangeId"],
            "capturedAt": observed_at(response.timestamp_start),
        }
        existing = self.capture_entries.get(request_key)
        if existing is not None:
            if existing["request"] == entry["request"] and existing["response"] == entry["response"]:
                return
            self.capture_entries.pop(request_key, None)
            self.ambiguous_request_keys.add(request_key)
            self.content_assurance_gaps.add("ambiguous-request-identity")
            return
        self.capture_entries[request_key] = entry

    @staticmethod
    def _write_all(descriptor: int, payload: bytes) -> None:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written < 1:
                raise OSError("private HTTP artifact write made no progress")
            view = view[written:]

    def _write_capture_manifest(self) -> None:
        if self.mode != "observe":
            return
        if not self.capture_entries:
            if self.counts["responses"] > 0:
                self.content_assurance_gaps.add("no-replayable-responses")
            self.content_manifest_digest = None
            return
        base = {
            "schemaVersion": 1,
            "apiVersion": API_VERSION,
            "kind": "NoshHttpContentManifest",
            "generatedAt": observed_at(),
            "runId": self.run_id,
            "mode": "offline-replay",
            "entries": sorted(
                self.capture_entries.values(),
                key=lambda entry: entry["requestKey"],
            ),
        }
        manifest = {**base, "contentHash": sha256(stable_json(base))}
        payload = f"{stable_json(manifest)}\n".encode("utf-8")
        if len(payload) > MANIFEST_MAX_BYTES:
            self.content_assurance_gaps.add("manifest-too-large")
            self.content_manifest_digest = None
            return
        assert self.cas_root is not None
        manifests = self.cas_root / "manifests"
        manifests.mkdir(mode=0o700, parents=True, exist_ok=True)
        if manifests.resolve() != manifests.absolute():
            raise ValueError("HTTP content manifest directory contains a symlink")
        details = manifests.lstat()
        if (
            not stat.S_ISDIR(details.st_mode)
            or stat.S_ISLNK(details.st_mode)
            or details.st_uid != os.geteuid()
        ):
            raise ValueError("HTTP content manifest directory is unsafe")
        manifests.chmod(0o700)
        hexadecimal = manifest["contentHash"].removeprefix("sha256:")
        destination = manifests / f"{hexadecimal}.json"
        temporary = self.cas_root / "tmp" / (
            f"{os.getpid()}.{os.urandom(16).hex()}.manifest"
        )
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            self._write_all(descriptor, payload)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, destination)
        except FileExistsError:
            existing_descriptor = os.open(
                destination,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                existing_details = os.fstat(existing_descriptor)
                if (
                    not stat.S_ISREG(existing_details.st_mode)
                    or existing_details.st_nlink != 1
                    or existing_details.st_uid != os.geteuid()
                    or stat.S_IMODE(existing_details.st_mode) != 0o400
                    or existing_details.st_size > MANIFEST_MAX_BYTES
                ):
                    raise ValueError("existing HTTP content manifest is unsafe")
                existing_chunks: list[bytes] = []
                remaining = existing_details.st_size
                while remaining:
                    chunk = os.read(
                        existing_descriptor,
                        min(1024 * 1024, remaining),
                    )
                    if not chunk:
                        break
                    existing_chunks.append(chunk)
                    remaining -= len(chunk)
                existing = b"".join(existing_chunks)
            finally:
                os.close(existing_descriptor)
            if existing != payload:
                raise ValueError("immutable HTTP content manifest already differs")
        finally:
            temporary.unlink(missing_ok=True)
        directory_descriptor = os.open(
            manifests,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        self.content_manifest_digest = manifest["contentHash"]

    def request(self, flow: Any) -> None:
        try:
            record = self._request_record(flow)
            flow.metadata["nosh_request_record"] = record
            self._emit(record)
            self.counts["requests"] += 1
            if self.mode != "observe" and record["credentialed"]:
                flow.response = http.Response.make(
                    403,
                    b"credentialed requests cannot use Nosh HTTP content gates\n",
                    {"Content-Type": "text/plain; charset=utf-8"},
                )
                self.content_assurance_gaps.add("credentialed-request")
                return
            if self.mode == "observe":
                return
            entry = self.entries.get(self._request_key(record))
            if entry is None:
                flow.response = http.Response.make(
                    403,
                    b"request is absent from the reviewed Nosh HTTP content manifest\n",
                    {"Content-Type": "text/plain; charset=utf-8"},
                )
                return
            flow.metadata["nosh_manifest_entry"] = entry
            if self.mode != "offline-replay":
                return
            response = entry["response"]
            body = self._read_cas(response["bodyDigest"], response["bodyBytes"])
            flow.response = self._response_from_entry(entry, body)
            flow.metadata["nosh_delivery"] = "cas"
        except Exception as error:
            self._fatal(flow, f"HTTP request gate failed: {error}")

    def requestheaders(self, flow: Any) -> None:
        try:
            flow.request.stream = False
        except Exception as error:
            self._fatal(flow, f"HTTP request buffering failed: {error}")

    def responseheaders(self, flow: Any) -> None:
        try:
            flow.response.stream = False
        except Exception as error:
            self._fatal(flow, f"HTTP response buffering failed: {error}")

    def response(self, flow: Any) -> None:
        try:
            request_record = flow.metadata.get("nosh_request_record")
            if request_record is None:
                request_record = self._request_record(flow)
                self._emit(request_record)
                self.counts["requests"] += 1
            response = flow.response
            raw_body = response.raw_content
            streamed = bool(response.stream)
            complete = raw_body is not None and not streamed
            if not complete:
                self.counts["incompleteBodies"] += 1
                self.incomplete_response_records += 1
                self.content_assurance_gaps.add("incomplete-response")
                self.coverage_gaps.add(
                    "streaming-response" if streamed else "incomplete-response-body"
                )
            if self.mode == "live-buffer-verify":
                entry = flow.metadata.get("nosh_manifest_entry")
                if entry is None:
                    # The request hook already rejected this before lazy upstream
                    # connection establishment. Do not reinterpret the local 403
                    # as an origin response.
                    return
                if not complete:
                    raise RuntimeError("live verification requires a fully buffered response")
                expected = entry["response"]
                if (
                    sha256(raw_body) != expected["bodyDigest"]
                    or len(raw_body) != expected["bodyBytes"]
                    or response.status_code != expected["status"]
                    or (response.headers.get("content-type") or None)
                        != expected.get("contentType")
                    or (response.headers.get("content-encoding") or None)
                        != expected.get("contentEncoding")
                    or (response.headers.get("location") or None)
                        != expected.get("location")
                ):
                    flow.response = http.Response.make(
                        502,
                        b"upstream response differs from reviewed Nosh content\n",
                        {"Content-Type": "text/plain; charset=utf-8"},
                    )
                    self.counts["errors"] += 1
                    self.coverage_gaps.add("capture-error")
                    return
                upstream_timestamp = response.timestamp_start
                flow.response = self._response_from_entry(entry, raw_body)
                flow.response.timestamp_start = upstream_timestamp
                response = flow.response
                flow.metadata["nosh_delivery"] = "buffered"
            elif self.mode == "observe" and complete:
                if len(raw_body) > self.maximum_body_bytes:
                    self.coverage_gaps.add("oversized-body")
                    self.content_assurance_gaps.add("oversized-body")
                elif request_record["credentialed"]:
                    self.content_assurance_gaps.add("credentialed-request")
                elif request_record["method"] == "HEAD":
                    self.content_assurance_gaps.add("head-response")
                elif response.status_code < 200:
                    self.content_assurance_gaps.add("interim-response")
                    self.coverage_gaps.add("interim-response")
                elif response.status_code == 304:
                    self.content_assurance_gaps.add("not-modified-response")
                elif record_range := (
                    response.status_code == 206
                    or bool(response.headers.get("content-range"))
                ):
                    self.content_assurance_gaps.add("range-response")
                else:
                    if self._write_cas(raw_body) is not None:
                        self._add_capture_entry(
                            request_record,
                            response,
                            raw_body,
                        )
            upstream_address = None
            upstream_port = None
            if flow.server_conn.peername is not None:
                upstream_address, upstream_port = connection_endpoint(
                    flow.server_conn.peername,
                    "proxy upstream endpoint",
                )
            record = {
                **self._common("http-response", response.timestamp_start),
                "exchangeId": self._exchange_id(flow),
                "status": response.status_code,
                "contentType": response.headers.get("content-type") or None,
                "contentEncoding": response.headers.get("content-encoding") or None,
                "headersDigest": response_headers_digest(response.headers),
                "bodyDigest": sha256(raw_body) if complete else None,
                "bodyBytes": len(raw_body) if complete else None,
                "decodedBodyDigest": None,
                "decodedBodyBytes": None,
                "bodyComplete": complete,
                "delivery": flow.metadata.get("nosh_delivery", "observed"),
                "rangeResponse": response.status_code == 206 or bool(
                    response.headers.get("content-range")
                ),
                "upstreamAddress": upstream_address,
                "upstreamPort": upstream_port,
            }
            if record["rangeResponse"]:
                self.coverage_gaps.add("range-response")
            self._emit(record)
            self.counts["responses"] += 1
            location = response.headers.get("location")
            if 300 <= response.status_code <= 399 and location:
                resolved = urljoin(flow.request.pretty_url, location)
                try:
                    rendered, _scheme, _hostname, _port = display_url(resolved)
                except ValueError:
                    rendered = None
                self._emit({
                    **self._common("http-redirect", response.timestamp_start),
                    "exchangeId": self._exchange_id(flow),
                    "status": response.status_code,
                    "locationDisplayUrl": rendered,
                    "locationDigest": sha256(location),
                })
                self.counts["redirects"] += 1
        except Exception as error:
            self._fatal(flow, f"HTTP response gate failed: {error}")

    def error(self, _flow: Any) -> None:
        self.counts["errors"] += 1
        self.counts["incompleteBodies"] += 1
        self.coverage_gaps.update({"capture-error", "missing-response"})

    def websocket_start(self, flow: Any) -> None:
        self.counts["opaqueConnects"] += 1
        self.coverage_gaps.add("opaque-connect")
        if self.mode != "observe":
            flow.kill()

    def _object_path(self, digest: str) -> Path:
        if not DIGEST.fullmatch(digest):
            raise ValueError("invalid HTTP CAS digest")
        assert self.cas_root is not None
        hexadecimal = digest.removeprefix("sha256:")
        return self.cas_root / "objects" / "sha256" / hexadecimal[:2] / hexadecimal

    def _write_cas(self, body: bytes) -> tuple[str, int] | None:
        digest = sha256(body)
        destination = self._object_path(digest)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if destination.parent.resolve() != destination.parent.absolute():
            raise ValueError("HTTP CAS object shard contains a symlink")
        shard_details = destination.parent.lstat()
        if (
            not stat.S_ISDIR(shard_details.st_mode)
            or stat.S_ISLNK(shard_details.st_mode)
            or shard_details.st_uid != os.geteuid()
        ):
            raise ValueError("HTTP CAS object shard is unsafe")
        destination.parent.chmod(0o700)
        if destination.exists():
            self._read_cas(digest, len(body))
            return digest, len(body)
        hexadecimal = digest.removeprefix("sha256:")
        if (
            len(self.cas_objects) >= self.maximum_cas_objects
            or self.cas_bytes + len(body) > self.maximum_cas_bytes
        ):
            self.content_assurance_gaps.add("cas-quota-exceeded")
            return None
        assert self.cas_root is not None
        temporary = self.cas_root / "tmp" / f"{os.getpid()}.{os.urandom(16).hex()}.part"
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            self._write_all(descriptor, body)
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
        try:
            os.link(temporary, destination)
            self.cas_objects.add(hexadecimal)
            self.cas_bytes += len(body)
            shard_descriptor = os.open(
                destination.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(shard_descriptor)
            finally:
                os.close(shard_descriptor)
        except FileExistsError:
            self._read_cas(digest, len(body))
        finally:
            temporary.unlink(missing_ok=True)
        return digest, len(body)

    def _read_cas(self, digest: str, expected_bytes: int) -> bytes:
        selected = self._object_path(digest)
        descriptor = os.open(selected, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_uid != os.geteuid()
                or stat.S_IMODE(details.st_mode) != 0o400
                or details.st_size != expected_bytes
            ):
                raise ValueError("HTTP CAS object metadata is invalid")
            chunks: list[bytes] = []
            bytes_read = 0
            while bytes_read < expected_bytes:
                chunk = os.read(descriptor, min(1024 * 1024, expected_bytes - bytes_read))
                if not chunk:
                    break
                chunks.append(chunk)
                bytes_read += len(chunk)
        finally:
            os.close(descriptor)
        body = b"".join(chunks)
        if len(body) != expected_bytes or sha256(body) != digest:
            raise ValueError("HTTP CAS object content is invalid")
        return body

    def _emit_stats(self, complete: bool) -> None:
        if self.stats_emitted or self.evidence_handle is None:
            return
        missing_responses = max(
            0,
            self.counts["requests"] - self.counts["responses"],
        )
        self.counts["incompleteBodies"] = (
            missing_responses + self.incomplete_response_records
        )
        if missing_responses:
            self.coverage_gaps.add("missing-response")
        selected_complete = complete and not self.coverage_gaps and not any(
            self.counts[name] for name in ("errors", "incompleteBodies", "droppedRecords")
        ) and self.counts["requests"] == self.counts["responses"]
        self._emit({
            **self._common("http-capture-stats"),
            "complete": selected_complete,
            **self.counts,
            "coverageGaps": sorted(self.coverage_gaps),
            "contentAssuranceGaps": sorted(self.content_assurance_gaps),
            "contentManifestDigest": self.content_manifest_digest,
            "collectorImageDigest": self.collector_image_digest,
            "collectorAddonDigest": self.collector_addon_digest,
            "collectorWrapperDigest": self.collector_wrapper_digest,
        }, terminal=True)
        self.stats_emitted = True

    def _fatal(self, flow: Any, message: str) -> None:
        self.counts["errors"] += 1
        self.coverage_gaps.add("capture-error")
        try:
            if flow is not None and http is not None:
                flow.response = http.Response.make(
                    502,
                    b"Nosh HTTP capture failed closed\n",
                    {"Content-Type": "text/plain; charset=utf-8"},
                )
            if ctx is not None:
                ctx.log.error(message)
            self._emit_stats(False)
        finally:
            if self.evidence_handle is not None:
                self.evidence_handle.flush()
            os._exit(70)

    def done(self) -> None:
        try:
            self._write_capture_manifest()
            self._emit_stats(True)
        except Exception as error:
            self._fatal(None, f"HTTP capture finalization failed: {error}")
        if self.evidence_handle is not None:
            self.evidence_handle.flush()
            os.fsync(self.evidence_handle.fileno())
            self.evidence_handle.close()
            self.evidence_handle = None


addons = [NoshHttpEvidence()]


def _self_test() -> None:
    rendered, scheme, hostname, port = display_url(
        "https://user:password@example.test/pkg/file.tgz?token=secret&v=1"
    )
    assert rendered == (
        "https://example.test/pkg/file.tgz?%3Credacted-key%3E=<redacted>&v=<redacted>"
    )
    assert (scheme, hostname, port) == ("https", "example.test", 443)
    assert "password" not in rendered and "secret" not in rendered
    request = {
        "method": "HEAD",
        "scheme": "https",
        "hostname": "example.test",
        "port": 443,
        "requestTargetDigest": sha256("/file"),
        "requestBodyDigest": None,
        "representationHeadersDigest": sha256("[]"),
        "credentialed": False,
    }
    entry = {
        "requestKey": sha256(stable_json(request)),
        "request": request,
        "response": {
            "status": 200,
            "bodyDigest": sha256(b""),
            "bodyBytes": 0,
            "contentType": None,
            "contentEncoding": None,
            "location": None,
            "locationDigest": None,
        },
        "sourceExchangeId": sha256("head-exchange"),
        "capturedAt": "2026-08-22T12:00:00.000Z",
    }
    base = {
        "schemaVersion": 1,
        "apiVersion": API_VERSION,
        "kind": "NoshHttpContentManifest",
        "generatedAt": "2026-08-22T12:00:00.000Z",
        "runId": "head-self-test",
        "mode": "offline-replay",
        "entries": [entry],
    }
    manifest = {**base, "contentHash": sha256(stable_json(base))}
    with tempfile.TemporaryDirectory() as directory:
        manifest_path = Path(directory) / "manifest.json"
        manifest_path.write_text(stable_json(manifest), encoding="utf-8")
        manifest_path.chmod(0o400)
        try:
            NoshHttpEvidence()._load_manifest(manifest_path)
        except ValueError as error:
            assert "request identity" in str(error)
        else:
            raise AssertionError("HEAD replay manifest was accepted")
        terminal_request = {**request, "method": "GET"}
        for invalid_status in (101, 206, 304):
            invalid_entry = {
                **entry,
                "request": terminal_request,
                "requestKey": sha256(stable_json(terminal_request)),
                "response": {**entry["response"], "status": invalid_status},
            }
            invalid_base = {**base, "entries": [invalid_entry]}
            invalid_manifest = {
                **invalid_base,
                "contentHash": sha256(stable_json(invalid_base)),
            }
            invalid_path = Path(directory) / f"status-{invalid_status}-manifest.json"
            invalid_path.write_text(
                stable_json(invalid_manifest), encoding="utf-8"
            )
            invalid_path.chmod(0o400)
            try:
                NoshHttpEvidence()._load_manifest(invalid_path)
            except ValueError as error:
                assert "body digest" in str(error)
            else:
                raise AssertionError(
                    f"{invalid_status} replay manifest was accepted"
                )

        stats_path = Path(directory) / "stats.ndjson"
        stats_collector = NoshHttpEvidence()
        stats_collector.run_id = "stats-self-test"
        stats_collector.mode = "live-buffer-verify"
        stats_collector.collector_image_digest = PINNED_IMAGE_DIGEST
        stats_collector.collector_addon_digest = sha256("addon")
        stats_collector.collector_wrapper_digest = sha256("wrapper")
        stats_collector.counts["requests"] = 1
        stats_collector.evidence_handle = stats_path.open("w+", encoding="utf-8")
        stats_collector._emit_stats(False)
        stats_collector.evidence_handle.seek(0)
        stats_record = json.loads(stats_collector.evidence_handle.read())
        stats_collector.evidence_handle.close()
        assert stats_record["requests"] == 1
        assert stats_record["responses"] == 0
        assert stats_record["incompleteBodies"] == 1
        assert "missing-response" in stats_record["coverageGaps"]

        quota_path = Path(directory) / "quota-stats.ndjson"
        quota_collector = NoshHttpEvidence()
        quota_collector.run_id = "quota-self-test"
        quota_collector.mode = "observe"
        quota_collector.collector_image_digest = PINNED_IMAGE_DIGEST
        quota_collector.collector_addon_digest = sha256("addon")
        quota_collector.collector_wrapper_digest = sha256("wrapper")
        quota_collector.maximum_evidence_bytes = 4096
        quota_collector.evidence_stats_reserve = 2048
        quota_collector.evidence_bytes = 2048
        quota_collector.evidence_handle = quota_path.open("w+", encoding="utf-8")
        try:
            quota_collector._emit({"probe": "must be rejected"})
        except RuntimeError as error:
            assert "bounded limit" in str(error)
        else:
            raise AssertionError("HTTP evidence byte limit was not enforced")
        quota_collector._emit_stats(False)
        quota_collector.evidence_handle.seek(0)
        quota_stats = json.loads(quota_collector.evidence_handle.read())
        quota_collector.evidence_handle.close()
        assert quota_stats["droppedRecords"] == 1
        assert {"dropped-records", "provider-loss"}.issubset(
            quota_stats["coverageGaps"]
        )


if __name__ == "__main__":
    if sys.argv[1:] != ["--self-test"]:
        raise SystemExit("usage: nosh-mitmproxy-addon.py --self-test")
    _self_test()
