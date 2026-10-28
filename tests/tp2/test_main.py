import json
import sys

from tp2.main import main


def test_main_generates_reports(tmp_path, monkeypatch):
    """Vérifie que la CLI génère un JSON et un PDF par échantillon."""
    samples_dir = tmp_path / "samples"
    rules_dir = tmp_path / "rules"
    output_dir = tmp_path / "reports"

    samples_dir.mkdir()
    rules_dir.mkdir()

    # Échantillons fictifs : aucun malware réel n'est nécessaire.
    (samples_dir / "sample1.bin").write_bytes(b"First test sample")
    (samples_dir / "sample2.bin").write_bytes(b"Second test sample")

    # Simule l'exécution de la commande tp2.
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

    # Vérifie le nombre de rapports générés.
    json_reports = sorted(output_dir.glob("*.triage.json"))
    pdf_reports = sorted(output_dir.glob("*.triage.pdf"))

    assert len(json_reports) == 2
    assert len(pdf_reports) == 2

    # Vérifie les informations présentes dans les JSON.
    for json_path in json_reports:
        data = json.loads(json_path.read_text(encoding="utf-8"))

        assert len(data["sha256"]) == 64
        assert len(data["md5"]) == 32
        assert "entropy" in data
        assert "iocs" in data
        assert "yara_matches" in data
        assert "family_guess" in data
        assert "mitre_attack" in data
        assert "score" in data
        assert "flag" in data

        # Chaque JSON doit avoir son PDF correspondant.
        pdf_path = json_path.with_suffix(".pdf")

        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 0
        assert pdf_path.read_bytes().startswith(b"%PDF-")