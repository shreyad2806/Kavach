"""
Artifact downloader — fetches an external artifact into quarantine S3.
Enforces a size limit and timeout so a malicious source can't stall the pipeline.
"""

import urllib.request
from urllib.error import URLError

MAX_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB hard limit
TIMEOUT_SECONDS = 15


class DownloadError(Exception):
    pass


class ArtifactTooLargeError(DownloadError):
    pass


def fetch(source_url: str) -> bytes:
    """
    Download artifact bytes from source_url.
    Raises DownloadError on network failure.
    Raises ArtifactTooLargeError if the artifact exceeds MAX_SIZE_BYTES.
    """
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
    except ArtifactTooLargeError:
        raise
    except URLError as e:
        raise DownloadError(f"Failed to download artifact from {source_url}: {e}") from e
    except Exception as e:
        raise DownloadError(f"Unexpected error downloading {source_url}: {e}") from e
