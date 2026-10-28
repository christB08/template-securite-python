import json
import sys

from tp2.main import main


def test_main_generates_reports(tmp_path, monkeypatch):
    """Vérifie que la CLI génère un JSON pour chaque échantillon."""
    samples_dir = tmp_path / "samples"
    rules_dir = tmp_path / "rules"
    output_dir = tmp_path / "reports"

    samples_dir.mkdir()
    rules_dir.mkdir()

    (samples_dir / "sample1.bin").write_bytes(b"First test sample")
    (samples_dir / "sample2.bin").write_bytes(b"Second test sample")

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "tp2",
            "--samples",
            str(samples_dir),
            "--rules",
            str(rules_dir),
            "--out",
            str(output_dir),
        ],
    )

    main()

    reports = sorted(output_dir.glob("*.triage.json"))

    assert len(reports) == 2

    for report_path in reports:
        data = json.loads(report_path.read_text(encoding="utf-8"))

        assert len(data["sha256"]) == 64
        assert "entropy" in data
        assert "iocs" in data