"""Image recipes retain British-spelled notices and Gate binary provenance."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_every_go_cache_notice_find_includes_both_license_spellings():
    docker = (ROOT / "Dockerfile").read_text()
    clauses = [
        line for line in docker.splitlines() if "find . -type f" in line and "license*" in line
    ]
    assert len(clauses) == 9
    assert all("-iname 'licence*'" in line for line in clauses)


def test_gate_provenance_is_retained_with_exact_binary_metadata():
    docker = (ROOT / "Dockerfile").read_text()
    gate = docker.split("AS gate-build\n", 1)[1].split("\nFROM ", 1)[0]
    assert "go version -m /out/vardrgate > /out/provenance/build-info.txt" in gate
    assert "cp go.mod go.sum LICENSE /out/provenance/" in gate
    assert "go mod verify" in gate
    assert "/out/provenance/dependency-notices.tar.gz" in gate
    assert "COPY --from=gate-build /out/provenance/ /opt/vardrtools/provenance/vardrgate/" in docker


def test_gate_binary_ignores_ambient_vcs_metadata():
    docker = (ROOT / "Dockerfile").read_text()
    gate = docker.split("AS gate-build\n", 1)[1].split("\nFROM ", 1)[0]
    assert "go build -trimpath -buildvcs=false -o /out/vardrgate" in gate
