"""
Thin wrapper around requests for authenticated calls to the VardrMap API.
Generic get/post/patch raise requests.HTTPError on non-2xx responses. The
job-lifecycle calls (claim_job, complete_job) instead raise classified
vardrrunner.errors.RunnerError subclasses, so callers can distinguish a
stop-work refusal from a claim race without inspecting status codes.

The session retries transient failures (connection errors and 429/5xx) with
exponential backoff so a long-running daemon survives network blips and brief
backend restarts. Retries are limited to idempotent methods (urllib3's default:
GET/HEAD/PUT/DELETE/OPTIONS/TRACE) — POST and PATCH are never auto-retried, so a
dropped response can't cause a double-claim, double-import, or duplicate event.
"""

import platform
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from vardrrunner import __version__, errors

# Statuses worth retrying: rate-limit + transient server/proxy errors.
_RETRY_STATUSES = (429, 500, 502, 503, 504)
PYPI_METADATA_URL = "https://pypi.org/pypi/vardrrunner/json"


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

    def whoami(self) -> dict:
        return self.get("/me")

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

    def import_file(self, engagement_id: str, tool_type: str, file_path: str) -> dict:
        with open(file_path, "rb") as fh:
            return self.post(
                f"/engagements/{engagement_id}/imports",
                files={"file": (file_path, fh, "application/json")},
                data={"tool_type": tool_type},
            )

    # ------------------------------------------------------------------
    # Scan jobs (job queue for UI-initiated scans)
    # ------------------------------------------------------------------

    def pending_jobs(self) -> list[dict]:
        """Return all pending jobs owned by the authenticated user."""
        return self.get("/jobs/pending").get("jobs", [])

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

    def create_services(self, engagement_id: str, services: list[dict]) -> dict:
        """Bulk-upsert nmap service results for an engagement."""
        return self.post(f"/engagements/{engagement_id}/services", json={"services": services})
