"""Indirect Prompt Injection Detector ΓÇö scans non-user content for hidden attacks.

Modern LLM applications frequently incorporate external data into the
context window (tool call results, fetched URLs, RAG chunks).  An attacker
can embed malicious instructions in those sources so the LLM executes them
as if they came from the user.

This module:
1. Extracts content from ``tool`` / ``function`` role messages.
2. Optionally extracts and fetches URLs found in any message.
3. Scans extracted content through the PatternMatcher and InputSanitizer.
4. Reports hidden instruction patterns (Markdown/HTML tricks, invisible
   Unicode, etc.) as ``ThreatInfo`` entries.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
import urllib.error
import urllib.request
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

if TYPE_CHECKING:
    from entropy.core.input_sanitizer import InputSanitizer
    from entropy.core.pattern_matcher import PatternMatcher

import structlog

from entropy.models.schemas import (
    ChatCompletionRequest,
    ThreatInfo,
    ThreatLevel,
)

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Heuristic patterns for indirect injection markers
# ---------------------------------------------------------------------------

# Instructions hidden inside HTML comments
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

# Hidden text via Markdown image alt-text abuse or zero-width chars
_INVISIBLE_UNICODE_RE = re.compile(
    r"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u200e\u200f"
    r"\u202a-\u202e\u2066-\u2069]+"
)

# Markdown link / image injection  (![](url){instructions})
_MD_INJECTION_RE = re.compile(
    r"!\[([^\]]*)\]\([^)]*\)\{([^}]+)\}",
    re.IGNORECASE,
)

# "System:" or "INSTRUCTIONS:" prefixes in non-user content
_INSTRUCTION_PREFIX_RE = re.compile(
    r"(?:^|\n)\s*(?:system|instruction|assistant|admin|operator)\s*[:>]",
    re.IGNORECASE,
)

# URL extraction pattern
_URL_RE = re.compile(
    r"https?://[^\s<>\"')\]]+",
    re.IGNORECASE,
)

# Ports that must never be fetched (SSRF risk even on public hosts)
_BLOCKED_PORTS = {22, 23, 25, 3306, 5432, 6379, 6380, 11211, 27017}


class _UnsafeFetchError(Exception):
    """Internal: a URL or hostname failed SSRF validation."""


def _is_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True only for globally routable addresses."""
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _is_url_shape_safe(url: str) -> bool:
    """Validate URL scheme, credentials, hostname, and port (no DNS lookup)."""
    try:
        parsed = urlparse(url)
        port = parsed.port
        hostname_ok = bool(parsed.hostname)
    except ValueError:
        return False

    scheme_ok = parsed.scheme in ("http", "https")
    creds_ok = not parsed.username and not parsed.password
    port_ok = port is None or (1 <= port <= 65535 and port not in _BLOCKED_PORTS)
    return scheme_ok and creds_ok and hostname_ok and port_ok


def _resolve_validated_ips(
    hostname: str,
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve *hostname* and return its public IP addresses.

    Raises :class:`_UnsafeFetchError` when resolution fails or any resolved
    address is private, loopback, link-local, multicast, reserved, or
    unspecified.  Connecting to a returned address — instead of resolving
    the hostname a second time — closes the DNS-rebinding TOCTOU window.
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
    except OSError as exc:
        raise _UnsafeFetchError(f"cannot resolve hostname {hostname!r}") from exc

    ips: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for _family, _socktype, _proto, _canonname, sockaddr in addr_infos:
        try:
            ip = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise _UnsafeFetchError(f"unparseable address for {hostname!r}") from exc
        if not _is_public_ip(ip):
            raise _UnsafeFetchError(f"{hostname!r} resolves to non-public address {ip}")
        ips.append(ip)

    if not ips:
        raise _UnsafeFetchError(f"{hostname!r} has no addresses")
    return ips


def _is_url_safe_to_fetch(url: str) -> bool:
    """Defensive SSRF check: only public HTTP(S) URLs without credentials.

    Validates the URL shape, then requires every resolved address to be
    public.  Used as a fail-fast pre-check; the actual connection pins a
    freshly validated address (see :class:`_ValidatedHTTPConnection`).
    """
    if not _is_url_shape_safe(url):
        return False
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    try:
        _resolve_validated_ips(hostname)
    except _UnsafeFetchError:
        return False
    return True


class _ValidatedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection pinned to a freshly validated public IP.

    The connection resolves the target hostname itself, validates every
    address, and connects to the validated result — there is no second,
    unvalidated resolution, so DNS rebinding cannot swap in an internal
    address between check and use.
    """

    def connect(self) -> None:
        ips = _resolve_validated_ips(self.host)
        self.sock = socket.create_connection((str(ips[0]), self.port), timeout=self.timeout)


class _ValidatedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a validated public IP.

    TLS SNI and certificate verification still use the original hostname,
    so IP pinning does not weaken certificate checks.
    """

    def __init__(self, *args: Any, context: ssl.SSLContext | None = None, **kwargs: Any) -> None:
        if context is None:
            context = ssl.create_default_context()
        super().__init__(*args, context=context, **kwargs)
        self.tls_context = context

    def connect(self) -> None:
        ips = _resolve_validated_ips(self.host)
        sock = socket.create_connection((str(ips[0]), self.port), timeout=self.timeout)
        self.sock = self.tls_context.wrap_socket(sock, server_hostname=self.host)


class _ValidatedHTTPHandler(urllib.request.HTTPHandler):
    """HTTP handler using connections pinned to validated public IPs."""

    def http_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(_ValidatedHTTPConnection, req)


class _ValidatedHTTPSHandler(urllib.request.HTTPSHandler):
    """HTTPS handler using connections pinned to validated public IPs."""

    def __init__(self, context: ssl.SSLContext) -> None:
        super().__init__(context=context)
        self.validated_context = context

    def https_open(self, req: urllib.request.Request) -> http.client.HTTPResponse:
        return self.do_open(_ValidatedHTTPSConnection, req, context=self.validated_context)


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect handler that validates every redirect target.

    ``urllib`` follows redirects by default, which would let a safe public
    URL bounce (302) to an internal address.  Each hop is re-validated
    here; the subsequent connection re-pins DNS as well.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: http.client.HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        if not _is_url_shape_safe(newurl):
            raise urllib.error.HTTPError(
                newurl, code, "blocked unsafe redirect target (SSRF)", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# ---------------------------------------------------------------------------
# IndirectInjectionDetector
# ---------------------------------------------------------------------------


class IndirectInjectionDetector:
    """Detect prompt injection vectors hidden in non-user content.

    Usage::

        detector = IndirectInjectionDetector(pattern_matcher, sanitizer)
        threats = detector.analyze(request)
    """

    def __init__(
        self,
        pattern_matcher: PatternMatcher,
        input_sanitizer: InputSanitizer,
        *,
        fetch_urls: bool = False,
    ) -> None:
        self.pattern_matcher = pattern_matcher
        self.input_sanitizer = input_sanitizer
        self.fetch_urls = fetch_urls

    # -- public API ---------------------------------------------------------

    def analyze(self, request: ChatCompletionRequest) -> list[ThreatInfo]:
        """Scan a request for indirect prompt injection vectors.

        Returns a list of ``ThreatInfo`` entries (may be empty for clean
        requests).
        """
        threats: list[ThreatInfo] = []

        # 1. Extract content from tool / function role messages
        tool_contents = self._extract_tool_content(request)
        for source, content in tool_contents:
            t = self._scan_content(content, source)
            threats.extend(t)

        # 2. Scan for hidden instructions in all messages
        all_content = self._extract_all_content(request)
        for source, content in all_content:
            t = self._scan_hidden_markers(content, source)
            threats.extend(t)

        # 3. Extract URLs from all messages (optional fetch)
        if self.fetch_urls:
            urls = self._extract_urls(request)
            for url in urls:
                fetched = self._fetch_url_content(url)
                if fetched:
                    t = self._scan_content(fetched, f"fetched_url:{url}")
                    threats.extend(t)

        if threats:
            logger.warning(
                "Indirect injection detected",
                threat_count=len(threats),
            )

        return threats

    # -- content extraction -------------------------------------------------

    @staticmethod
    def _extract_tool_content(request: ChatCompletionRequest) -> list[tuple[str, str]]:
        """Extract text from tool / function role messages."""
        results: list[tuple[str, str]] = []
        for i, msg in enumerate(request.messages):
            if msg.role not in ("tool", "function"):
                continue
            content = ""
            if isinstance(msg.content, str):
                content = msg.content
            elif isinstance(msg.content, list):
                for item in msg.content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        content += item.get("text", "")
            if content.strip():
                source = f"tool_msg[{i}]"
                if msg.name:
                    source = f"tool:{msg.name}"
                results.append((source, content))
        return results

    @staticmethod
    def _extract_all_content(request: ChatCompletionRequest) -> list[tuple[str, str]]:
        """Extract text from ALL messages for hidden-marker scanning.

        Includes image alt text and function/tool-call argument values so
        hidden markers in those surfaces are scanned like any other field.
        """
        from entropy.core.content_extraction import iter_request_texts  # noqa: PLC0415

        return iter_request_texts(request)

    def _extract_urls(self, request: ChatCompletionRequest) -> list[str]:
        """Extract URLs found in any message content."""
        urls: list[str] = []
        for msg in request.messages:
            text = ""
            if isinstance(msg.content, str):
                text = msg.content
            elif isinstance(msg.content, list):
                for item in msg.content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text += item.get("text", "")
            urls.extend(_URL_RE.findall(text))
        return list(set(urls))  # deduplicate

    # -- scanning -----------------------------------------------------------

    def _scan_content(self, content: str, source: str) -> list[ThreatInfo]:
        """Run full pattern matcher + sanitizer scan on content."""
        threats: list[ThreatInfo] = []

        # Decode obfuscation layers first
        sanitized = self.input_sanitizer.sanitize(content)
        analysis_text = sanitized.decoded

        if sanitized.was_obfuscated:
            threats.append(
                ThreatInfo(
                    category="indirect_injection",
                    name="obfuscated_tool_output",
                    threat_level=ThreatLevel.HIGH,
                    confidence=min(0.4 * sanitized.layers_decoded, 0.95),
                    details=(
                        f"Obfuscated content in {source}: {', '.join(sanitized.encodings_found)}"
                    ),
                )
            )

        # Pattern matching on decoded content
        is_malicious, confidence, detections, threat_level = self.pattern_matcher.analyze(
            analysis_text
        )

        if is_malicious:
            # Boost severity: injection patterns in tool output are more dangerous
            boosted_level = ThreatLevel.HIGH
            if threat_level == ThreatLevel.CRITICAL:
                boosted_level = ThreatLevel.CRITICAL

            threats.append(
                ThreatInfo(
                    category="indirect_injection",
                    name="injection_in_external_content",
                    threat_level=boosted_level,
                    confidence=min(confidence + 0.15, 1.0),
                    details=(
                        f"Injection pattern found in {source}: "
                        f"{', '.join(d.pattern_name for d in detections[:3])}"
                    ),
                )
            )

        return threats

    def _scan_hidden_markers(self, content: str, source: str) -> list[ThreatInfo]:
        """Detect hidden instruction markers in content."""
        threats: list[ThreatInfo] = []

        # HTML comments with instruction-like content
        for match in _HTML_COMMENT_RE.finditer(content):
            comment_text = match.group(1).strip()
            if len(comment_text) > 10:
                # Check if the comment contains injection patterns
                is_mal, conf, _, _ = self.pattern_matcher.analyze(comment_text)
                if is_mal:
                    threats.append(
                        ThreatInfo(
                            category="indirect_injection",
                            name="hidden_html_comment",
                            threat_level=ThreatLevel.HIGH,
                            confidence=min(conf + 0.1, 1.0),
                            details=(f"Malicious instructions hidden in HTML comment in {source}"),
                        )
                    )

        # Invisible Unicode characters hiding instructions
        invisible_matches = _INVISIBLE_UNICODE_RE.findall(content)
        if invisible_matches:
            total_invisible = sum(len(m) for m in invisible_matches)
            if total_invisible > 5:
                threats.append(
                    ThreatInfo(
                        category="indirect_injection",
                        name="invisible_unicode_chars",
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=min(0.2 * total_invisible, 0.85),
                        details=(
                            f"{total_invisible} invisible Unicode characters found in {source}"
                        ),
                    )
                )

        # Instruction prefixes in non-user content  (e.g. "System: do X")
        if "tool" in source or "function" in source:
            prefix_matches = _INSTRUCTION_PREFIX_RE.findall(content)
            if prefix_matches:
                threats.append(
                    ThreatInfo(
                        category="indirect_injection",
                        name="instruction_prefix_in_tool_output",
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.8,
                        details=(
                            f"Instruction prefix pattern found in {source} ΓÇö "
                            f"possible attempt to override system instructions"
                        ),
                    )
                )

        # Markdown injection patterns
        md_matches = _MD_INJECTION_RE.findall(content)
        if md_matches:
            threats.append(
                ThreatInfo(
                    category="indirect_injection",
                    name="markdown_injection",
                    threat_level=ThreatLevel.MEDIUM,
                    confidence=0.7,
                    details=f"Markdown injection pattern found in {source}",
                )
            )

        return threats

    # -- URL fetching (optional) --------------------------------------------

    @staticmethod
    def _fetch_url_content(url: str) -> str | None:
        """Fetch and return text content from a URL.

        Returns None on any error.  This is intentionally conservative:
        short timeout, max size, no proxy support, per-hop redirect
        validation, and connections pinned to freshly validated public
        IPs (SSRF protection including DNS rebinding).
        """
        if not _is_url_safe_to_fetch(url):
            logger.warning("Blocked unsafe URL fetch (SSRF protection)", url=url)
            return None
        try:
            context = ssl.create_default_context()
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}),  # never use environment proxies
                _ValidatedHTTPHandler(),
                _ValidatedHTTPSHandler(context=context),
                _SafeRedirectHandler(),
            )
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "EntropyFirewall/0.1"},
            )
            with opener.open(req, timeout=3) as resp:
                # Max 100KB to prevent resource abuse
                data: bytes = resp.read(102_400)
                return data.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug("Failed to fetch URL for analysis", url=url, error=str(e))
            return None
