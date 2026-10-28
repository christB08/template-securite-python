import json

from tp2.utils.report import Report


def test_generate_json(tmp_path):
    """Vérifie la création et le contenu d'un rapport JSON."""
    result = {
        "sha256": "abc123",
        "entropy": 4.8,
        "yara_matches": ["Test_Rule"],
    }

    output_path = tmp_path / "reports" / "sample.triage.json"

    Report(result).generate_json(str(output_path))

    assert output_path.exists()

    content = json.loads(output_path.read_text(encoding="utf-8"))

    assert content["sha256"] == "abc123"
    assert content["entropy"] == 4.8
    assert content["yara_matches"] == ["Test_Rule"]


def test_generate_pdf(tmp_path):
    """Vérifie qu'un rapport PDF valide est créé."""
    from tp2.utils.report import Report

    result = {
        "sha256": "abc123",
        "md5": "def456",
        "size": 1024,
        "file_type": "ELF",
        "entropy": 4.8,
        "score": 8,
        "family_guess": "potential_backdoor",
        "flag": "ESGI{test_flag}",
        "yara_matches": ["Potential_C2_Communication"],
        "mitre_attack": ["T1071.001"],
        "iocs": {
            "urls": ["http://example.test/gate.php"],
            "ips": ["192.0.2.1"],
        },
        "imports": ["printf"],
        "sections": [".text"],
        "llm_summary": "Analyse statique locale, sans LLM.",
    }

    output = tmp_path / "rapport.pdf"

    Report(result).generate_pdf(str(output))

    assert output.exists()
    assert output.stat().st_size > 0
    assert output.read_bytes().startswith(b"%PDF-")