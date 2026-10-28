from src.tp2.utils.scanner import YaraScanner


def test_yara_scan_match(tmp_path):
    """Vérifie qu'une règle détecte une chaîne présente."""
    rules_file = tmp_path / "test.yar"

    rules_file.write_text(
        """
rule Detect_Test_String
{
    strings:
        $test = "malware_test"

    condition:
        $test
}
""",
        encoding="utf-8",
    )

    scanner = YaraScanner(str(rules_file))
    result = scanner.scan(b"This contains malware_test")

    assert "Detect_Test_String" in result


def test_yara_scan_no_match(tmp_path):
    """Vérifie qu'une règle ne se déclenche pas sans correspondance."""
    rules_file = tmp_path / "test.yar"

    rules_file.write_text(
        """
rule Detect_Test_String
{
    strings:
        $test = "malware_test"

    condition:
        $test
}
""",
        encoding="utf-8",
    )

    scanner = YaraScanner(str(rules_file))
    result = scanner.scan(b"Hello world")

    assert result == []


def test_yara_scan_missing_rules(tmp_path):
    """Vérifie la gestion d'un chemin de règles inexistant."""
    scanner = YaraScanner(str(tmp_path / "missing"))

    result = scanner.scan(b"test")

    assert result == []