"""
Recon pipeline definitions.

A pipeline is a named, ordered list of stages. Each stage runs a tool handler and
uploads its results to VardrMap; the next stage pulls those results via the `recon`
source. So `recon` chains subfinder (enumerate subdomains from wildcard scope) →
httpx (probe the discovered hosts) → nuclei (scan the live ones), each handing off
to the next through the backend's recon store.

Add a pipeline by adding an entry here — stages reference handlers in the registry.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Stage:
    tool: str  # must match a key in handlers.REGISTRY
    source: str  # "scope" | "recon" — where this stage resolves its targets


PIPELINES: dict[str, list[Stage]] = {
    # Full recon: enumerate subdomains → probe which are alive → scan the live ones.
    "recon": [
        Stage("subfinder", "scope"),
        Stage("httpx", "recon"),
        Stage("nuclei", "recon"),
    ],
    # Lightweight: just discover and probe, no vulnerability scan.
    "quick": [
        Stage("subfinder", "scope"),
        Stage("httpx", "recon"),
    ],
    # Deep recon: resolve discovered subdomains with dnsx before probing, so httpx
    # and nuclei only see hosts that actually exist.
    "deep": [
        Stage("subfinder", "scope"),
        Stage("dnsx", "recon"),
        Stage("httpx", "recon"),
        Stage("nuclei", "recon"),
    ],
    # Port discovery: enumerate → resolve → fast port-scan with naabu (→ services).
    "ports": [
        Stage("subfinder", "scope"),
        Stage("dnsx", "recon"),
        Stage("naabu", "recon"),
    ],
    # Content discovery: find the live hosts, crawl them for endpoints (katana),
    # and pull historical URLs for the scope domains from public archives (gau).
    # katana feeds on the live hosts httpx found; gau reads the wildcard scope
    # independently, so it runs last and adds to the same recon store.
    "content": [
        Stage("subfinder", "scope"),
        Stage("httpx", "recon"),
        Stage("katana", "recon"),
        Stage("gau", "scope"),
    ],
}
