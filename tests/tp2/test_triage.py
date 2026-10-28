from tp2.utils.triage import Triage


def test_triage_run(tmp_path):
    """Vérifie que le triage rassemble les résultats de l'analyse."""
    sample_path = tmp_path / "test.bin"
    sample_path.write_bytes(b"Hello world")

    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    result = Triage(str(sample_path), str(rules_dir)).run()

    assert len(result["sha256"]) == 64
    assert result["size"] == 11
    assert isinstance(result["entropy"], float)
    assert isinstance(result["iocs"], dict)
    assert isinstance(result["imports"], list)
    assert isinstance(result["yara_matches"], list)