from tp2.utils.summary import generate_local_summary


def test_generate_local_summary():
    """Vérifie que le résumé contient les principaux résultats."""
    summary = generate_local_summary(
        family_guess="potential_keylogger",
        score=8,
        yara_matches=["Potential_Keylogging_Indicators"],
        mitre_attack=["T1056.001"],
    )

    assert "capture clavier" in summary
    assert "8/10" in summary
    assert "Potential_Keylogging_Indicators" in summary
    assert "T1056.001" in summary


def test_generate_local_summary_without_indicators():
    """Vérifie le résumé lorsqu'aucun indice n'est détecté."""
    summary = generate_local_summary(
        family_guess="unknown",
        score=0,
        yara_matches=[],
        mitre_attack=[],
    )

    assert "aucune correspondance" in summary
    assert "aucune technique associée" in summary