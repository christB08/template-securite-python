from tp2.utils.classification import classify_sample


def test_classify_keylogger():
    """Les indices de capture clavier sont prioritaires."""
    family, techniques = classify_sample(
        yara_matches=[
            "Potential_C2_Communication",
            "Potential_Keylogging_Indicators",
        ],
        entropy=4.8,
    )

    assert family == "potential_keylogger"
    assert "T1056.001" in techniques
    assert "T1071.001" in techniques


def test_classify_packed():
    """Une entropie élevée suggère un contenu potentiellement packé."""
    family, techniques = classify_sample(
        yara_matches=[],
        entropy=7.8,
    )

    assert family == "potential_packed"
    assert techniques == []


def test_classify_backdoor():
    """Des indices C2 suggèrent une possible backdoor."""
    family, techniques = classify_sample(
        yara_matches=["Potential_C2_Communication"],
        entropy=4.5,
    )

    assert family == "potential_backdoor"
    assert techniques == ["T1071.001"]


def test_classify_unknown():
    """Sans indice pertinent, la famille reste inconnue."""
    family, techniques = classify_sample(
        yara_matches=[],
        entropy=4.0,
    )

    assert family == "unknown"
    assert techniques == []