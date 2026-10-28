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