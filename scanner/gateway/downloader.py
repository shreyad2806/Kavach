"""
Artifact downloader — fetches an external artifact into quarantine S3.
Enforces a size limit and timeout so a malicious source can't stall the pipeline.

SSRF protection: blocks requests to private IP ranges, link-local addresses,
localhost, and the AWS EC2 metadata endpoint before any connection is made.
"""

import ipaddress
import socket
import urllib.parse
import urllib.request
from urllib.error import URLError

MAX_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB hard limit
TIMEOUT_SECONDS = 15

# Private / reserved ranges that must never be fetched
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("169.254.0.0/16"),    # link-local / AWS metadata
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]


class DownloadError(Exception):
    pass


class ArtifactTooLargeError(DownloadError):
    pass


class SSRFBlockedError(DownloadError):
    pass


def _check_ssrf(url: str) -> None:
    """
    Resolve the hostname in url and raise SSRFBlockedError if it points
    to any private, loopback, or link-local address.
    Raises DownloadError if the hostname cannot be resolved.
    """
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise DownloadError(f"Invalid URL — no hostname: {url}")

    # Block bare 'localhost' and variants before DNS resolution
    if hostname.lower() in ("localhost", "localhost.localdomain", "ip6-localhost"):
        raise SSRFBlockedError(f"SSRF blocked: hostname '{hostname}' is not allowed")

    try:
        # getaddrinfo returns all addresses for the hostname
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise DownloadError(f"Failed to resolve hostname '{hostname}': {e}") from e

    for result in results:
        addr_str = result[4][0]
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            continue
        for blocked in _BLOCKED_NETWORKS:
            if addr in blocked:
                raise SSRFBlockedError(
                    f"SSRF blocked: '{hostname}' resolves to private/reserved address {addr_str}"
                )


def fetch(source_url: str) -> bytes:
    """
    Download artifact bytes from source_url.
    Raises SSRFBlockedError if the URL resolves to a private address.
    Raises DownloadError on network failure.
    Raises ArtifactTooLargeError if the artifact exceeds MAX_SIZE_BYTES.
    """
    _check_ssrf(source_url)

    try:
        with urllib.request.urlopen(source_url, timeout=TIMEOUT_SECONDS) as resp:
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_SIZE_BYTES:
                raise ArtifactTooLargeError(
                    f"Artifact exceeds size limit: {content_length} bytes (max {MAX_SIZE_BYTES})"
                )
            data = resp.read(MAX_SIZE_BYTES + 1)
            if len(data) > MAX_SIZE_BYTES:
                raise ArtifactTooLargeError(
                    f"Artifact exceeds size limit of {MAX_SIZE_BYTES} bytes"
                )
            return data
    except (ArtifactTooLargeError, SSRFBlockedError):
        raise
    except URLError as e:
        raise DownloadError(f"Failed to download artifact from {source_url}: {e}") from e
    except Exception as e:
        raise DownloadError(f"Unexpected error downloading {source_url}: {e}") from e
