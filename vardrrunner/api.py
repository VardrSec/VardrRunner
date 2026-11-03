"""
Thin wrapper around requests for authenticated calls to the VardrMap API.
Generic get/post/patch raise requests.HTTPError on non-2xx responses. The
job-lifecycle calls (claim_job, complete_job) instead raise classified
vardrrunner.errors.RunnerError subclasses, so callers can distinguish a
stop-work refusal from a claim race without inspecting status codes.

The session retries transient failures (connection errors and 429/5xx) with
exponential backoff so a `jobs run` survives network blips and brief backend
restarts. Retries are limited to idempotent methods (urllib3's default:
GET/HEAD/PUT/DELETE/OPTIONS/TRACE) — POST and PATCH are never auto-retried, so a
dropped response can't cause a double-claim, double-import, or duplicate event.
"""

import math
import platform
import re
import urllib.parse
from pathlib import Path
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from vardrrunner import __version__, errors

# Statuses worth retrying: rate-limit + transient server/proxy errors.
_RETRY_STATUSES = (429, 500, 502, 503, 504)
PYPI_METADATA_URL = "https://pypi.org/pypi/vardrrunner/json"
_MANAGED_REQUEST_BYTES = 1024 * 1024
_MANAGED_RESPONSE_BYTES = 256 * 1024


class ManagedTransportError(RuntimeError):
    """A fixed transport failure; never includes credentials or response bodies."""


class _ManagedHeaderAuth(requests.auth.AuthBase):
    def __call__(self, request):
        # Prevent requests' implicit netrc lookup from replacing the configured key.
        return request


class ReleaseMetadataError(RuntimeError):
    """The public package registry could not provide valid release metadata."""


def fetch_release_metadata(timeout: int = 10) -> dict:
    """Fetch public package metadata for the opt-in release check."""
    try:
        response = requests.get(PYPI_METADATA_URL, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise ReleaseMetadataError("package registry request failed") from exc
    if not isinstance(payload, dict):
        raise ReleaseMetadataError("package registry returned a non-object response")
    return payload


class AssetDownloadError(RuntimeError):
    """A pinned tool release asset could not be downloaded."""


def download_asset(url: str, dest: Path, *, max_bytes: int, timeout: int = 60) -> None:
    """Stream a public release asset to ``dest``, refusing anything over ``max_bytes``.

    Integrity is not checked here: the caller verifies the file against the hash
    pinned in the tool manifest before trusting a single byte of it. This only
    guarantees HTTPS and a bounded download, so a hostile or broken mirror can't
    fill the disk.
    """
    if urllib.parse.urlsplit(url).scheme != "https":
        raise AssetDownloadError("tool assets must be downloaded over HTTPS")
    received = 0
    try:
        with requests.get(url, stream=True, timeout=timeout) as response:
            response.raise_for_status()
            if urllib.parse.urlsplit(response.url).scheme != "https":
                raise AssetDownloadError("tool asset download was redirected off HTTPS")
            with dest.open("wb") as fh:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    received += len(chunk)
                    if received > max_bytes:
                        raise AssetDownloadError(
                            f"tool asset exceeded the {max_bytes} byte download limit"
                        )
                    fh.write(chunk)
    except requests.RequestException as exc:
        raise AssetDownloadError("tool asset download failed") from exc


class VardrMapClient:
    def __init__(
        self,
        api_url: str,
        api_key: str,
        *,
        retries: int = 3,
        backoff_factor: float = 0.5,
    ):
        self.base = api_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                # Identify the runner + version in backend logs.
                "User-Agent": f"vardrrunner/{__version__} ({platform.system()})",
            }
        )

        # Mount a retry-with-backoff adapter for transient failures. allowed_methods
        # is left at urllib3's idempotent-only default so POST/PATCH are not retried.
        retry = Retry(
            total=retries,
            connect=retries,
            read=retries,
            status=retries,
            backoff_factor=backoff_factor,
            status_forcelist=_RETRY_STATUSES,
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _url(self, path: str) -> str:
        return f"{self.base}/{path.lstrip('/')}"

    def get(self, path: str, params: dict | None = None) -> Any:
        r = self.session.get(self._url(path), params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    def post(
        self,
        path: str,
        json: dict | None = None,
        files: dict | None = None,
        data: dict | None = None,
    ) -> Any:
        r = self.session.post(self._url(path), json=json, files=files, data=data, timeout=60)
        r.raise_for_status()
        return r.json()

    def managed_post(
        self, path: str, payload: dict, *, timeout: tuple[float, float] = (3.05, 3)
    ) -> dict:
        """Explicit bounded JSON transport; no route, enrollment or execution activation.

        Use a fresh one-shot session so legacy retry/cookie defaults cannot apply.
        Timeouts bound connect/read-idle waits, not total wall-clock transfer time;
        managed callers retain their original signed/monotonic permission ceilings.
        """
        from vardrrunner.authorization.codec import decoded, encoded, require
        from vardrrunner.authorization.plan import origin

        try:
            parts = urllib.parse.urlsplit(self.base)
            origin(self.base)
            require(
                parts.scheme == "https"
                and parts.path in {"", "/"}
                and not parts.query
                and "?" not in self.base
                and "#" not in self.base
                and (
                    self.session.verify is True
                    or (type(self.session.verify) is str and bool(self.session.verify))
                )
                and isinstance(path, str)
                and len(path) <= 512
                and re.fullmatch(r"/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*", path) is not None
                and type(payload) is dict
                and type(timeout) is tuple
                and len(timeout) == 2
                and all(
                    type(v) in (int, float) and math.isfinite(v) and 0 < v <= 10 for v in timeout
                ),
                "invalid_managed_transport",
            )
            body = encoded(payload)
            require(len(body) <= _MANAGED_REQUEST_BYTES, "managed_request_size")
            with requests.Session() as session:
                session.auth = _ManagedHeaderAuth()
                session.trust_env = self.session.trust_env
                session.verify, session.cert = self.session.verify, self.session.cert
                session.proxies.update(self.session.proxies)
                session.headers.update(
                    {
                        "Authorization": self.session.headers["Authorization"],
                        "User-Agent": self.session.headers["User-Agent"],
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "Accept-Encoding": "identity",
                    }
                )
                session.mount("https://", HTTPAdapter(max_retries=0))
                with session.post(
                    self._url(path), data=body, timeout=timeout, stream=True, allow_redirects=False
                ) as response:
                    length = response.headers.get("Content-Length")
                    require(
                        response.status_code == 200
                        and response.headers.get("Content-Type", "").split(";")[0].lower()
                        == "application/json"
                        and response.headers.get("Content-Encoding", "identity").lower()
                        == "identity"
                        and (
                            length is None
                            or (
                                length.isascii()
                                and length.isdecimal()
                                and int(length) <= _MANAGED_RESPONSE_BYTES
                            )
                        ),
                        "invalid_managed_response",
                    )
                    data = bytearray()
                    for chunk in response.iter_content(chunk_size=1024):
                        require(
                            len(data) + len(chunk) <= _MANAGED_RESPONSE_BYTES,
                            "managed_response_size",
                        )
                        data.extend(chunk)
                    result = decoded(bytes(data), _MANAGED_RESPONSE_BYTES)
                    require(type(result) is dict, "managed_response_object")
                    encoded(result)  # Reject exponent overflow/nonfinite decoded numbers too.
                    return result
        except (
            requests.RequestException,
            ValueError,
            TypeError,
            KeyError,
            OverflowError,
            RecursionError,
        ):
            raise ManagedTransportError("managed request failed") from None

    def whoami(self) -> dict:
        return self.get("/me")

    def platform_readiness(self) -> dict:
        """Read the value-free v1 readiness contract, including explicit 503 states."""
        response = self.session.get(self._url("/ready"), timeout=(3.05, 10), allow_redirects=False)
        if response.status_code not in (200, 503):
            response.raise_for_status()
            raise ValueError("unsupported readiness HTTP response")
        data = response.json()
        if (
            not isinstance(data, dict)
            or type(data.get("schema_version")) is not int
            or data["schema_version"] != 1
            or data.get("component") != "vardrmap-api"
            or data.get("status") not in ("ready", "not_ready")
            or not isinstance(data.get("checks"), dict)
        ):
            raise ValueError("unsupported readiness contract")
        checks = data["checks"]
        database, migrations = checks.get("database"), checks.get("migrations")
        if database not in ("ok", "unavailable") or migrations not in (
            "current",
            "not_current",
            "unavailable",
            "not_checked",
        ):
            raise ValueError("unsupported readiness checks")
        ready = database == "ok" and migrations == "current"
        if (
            (data["status"] == "ready") != ready
            or (response.status_code == 200) != ready
            or (database == "unavailable") != (migrations == "not_checked")
        ):
            raise ValueError("inconsistent readiness contract")
        return {"database": database, "migrations": migrations}

    def engagements(self) -> list[dict]:
        data = self.get("/engagements")
        # VardrMap returns both keys during the programs → engagements
        # transition; prefer the new name and fall back to the old one.
        return data.get("engagements") or data.get("programs", [])

    def engagement(self, engagement_id: str) -> dict:
        return self.get(f"/engagements/{engagement_id}")

    def scope(self, engagement_id: str) -> dict:
        """Returns {"in": [...], "out": [...]} scope lists."""
        return self.engagement(engagement_id).get("scope", {"in": [], "out": []})

    # Backend rejects limit values above this with 422.
    RECON_PAGE_SIZE = 500

    def recon(
        self, engagement_id: str, limit: int = 100, status_code: int | None = None
    ) -> list[dict]:
        """Fetch recon items, paginating in RECON_PAGE_SIZE chunks to avoid backend 422s."""
        results: list[dict] = []
        offset = 0
        page_size = min(limit, self.RECON_PAGE_SIZE)

        while len(results) < limit:
            remaining = limit - len(results)
            fetch = min(remaining, page_size)
            params: dict = {"limit": fetch, "offset": offset}
            if status_code is not None:
                params["status_code"] = status_code
            page = self.get(f"/engagements/{engagement_id}/recon", params=params).get("recon", [])
            results.extend(page)
            if len(page) < fetch:
                break
            offset += fetch

        return results

    def import_file(
        self, engagement_id: str, tool_type: str, file_path: str, job_id: str = ""
    ) -> dict:
        with open(file_path, "rb") as fh:
            return self.post(
                f"/engagements/{engagement_id}/imports",
                files={"file": (file_path, fh, "application/json")},
                data={"tool_type": tool_type, **({"job_id": job_id} if job_id else {})},
            )

    # ------------------------------------------------------------------
    # Scan jobs (job queue for UI-initiated scans)
    # ------------------------------------------------------------------

    def pending_jobs(self) -> list[dict]:
        """Return all pending jobs owned by the authenticated user."""
        jobs = self.get("/jobs/pending").get("jobs", [])
        # The backend retains program_id on the wire for existing clients.
        # Keep both fields so envelope validation can reject conflicting IDs.
        return [
            {**job, "engagement_id": job["program_id"]}
            if not job.get("engagement_id") and job.get("program_id")
            else dict(job)
            for job in jobs
        ]

    def _classified(self, response: requests.Response) -> dict:
        """Return parsed JSON, or raise a classified domain error on non-2xx.

        Used on the job-lifecycle calls, where the runner must tell a stop-work
        refusal apart from a lost claim race, an expired key and a backend
        outage. The generic get/post/patch keep raising ``requests.HTTPError``
        so existing diagnostic callers are unaffected.
        """
        if response.ok:
            return response.json()
        try:
            body = response.json()
        except ValueError:
            body = None
        raise errors.classify_status(response.status_code, body) from requests.HTTPError(
            f"HTTP {response.status_code}", response=response
        )

    def claim_job(self, job_id: str) -> dict:
        """Atomically claim a pending job.

        Raises :class:`~vardrrunner.errors.ClaimRace` when another runner won,
        :class:`~vardrrunner.errors.StopWorkError` when the engagement's halt
        switch is engaged, and other :class:`~vardrrunner.errors.RunnerError`
        subclasses for auth and backend failures. The returned dict carries a
        ``warnings`` array of advisory policy findings.
        """
        r = self.session.post(self._url(f"/jobs/{job_id}/claim"), timeout=60)
        return self._classified(r)

    def complete_job(self, job_id: str, status: str, error: str = "") -> dict:
        """Mark a job done or failed."""
        payload: dict = {"status": status}
        if error:
            payload["error_message"] = error
        r = self.session.patch(self._url(f"/jobs/{job_id}"), json=payload, timeout=30)
        return self._classified(r)

    def claim_controlled(
        self,
        job_id: str,
        runner_id: str,
        *,
        concurrency_budget: bool = False,
        target_binding: dict | None = None,
        duration_seconds: int | None = None,
    ) -> dict:
        """Explicit companion capability; old servers must refuse, never fall back."""
        response = self.session.post(
            self._url(f"/jobs/{job_id}/claim"),
            json={
                "runner_id": runner_id,
                "origin": self.base,
                **({"concurrency_budget": True} if concurrency_budget else {}),
                **({"target_binding": target_binding} if target_binding is not None else {}),
                **({"duration_seconds": duration_seconds} if duration_seconds is not None else {}),
            },
            timeout=(1, 1),
            allow_redirects=False,
        )
        return self._classified(response)

    def execution_control(self, job_id: str, payload: dict, *, finish: bool = False) -> dict:
        """No redirects or retries for capability-bearing control messages."""
        endpoint = "execution-finish" if finish else "control"
        response = self.session.post(
            self._url(f"/jobs/{job_id}/{endpoint}"),
            json=payload,
            timeout=(1, 1),
            allow_redirects=False,
        )
        return self._classified(response)

    def patch(self, path: str, json: dict | None = None) -> Any:
        r = self.session.patch(self._url(path), json=json, timeout=30)
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Runner heartbeat
    # ------------------------------------------------------------------

    def send_heartbeat(self, payload: dict) -> dict:
        """Post runner status (hostname, version, os, tools) to the backend."""
        return self.post("/runner/heartbeat", json=payload)

    # ------------------------------------------------------------------
    # Job events
    # ------------------------------------------------------------------

    def post_event(self, job_id: str, kind: str, text: str = "") -> dict:
        """Post a lifecycle event for a job (started, running, done, failed, …)."""
        return self.post(f"/jobs/{job_id}/events", json={"kind": kind, "text": text})

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def create_services(self, engagement_id: str, services: list[dict], job_id: str = "") -> dict:
        """Bulk-upsert nmap service results for an engagement."""
        return self.post(
            f"/engagements/{engagement_id}/services",
            json={"services": services, **({"job_id": job_id} if job_id else {})},
        )
