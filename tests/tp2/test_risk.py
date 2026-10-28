from tp2.utils.risk import calculate_risk_score


def test_risk_score_without_indicators():
    """Un fichier sans indicateur obtient un score nul."""
    score = calculate_risk_score(
        entropy=4.0,
        iocs={},
        yara_matches=[],
    )

    assert score == 0


def test_risk_score_with_indicators():
    """Les indicateurs suspects augmentent le score."""
    score = calculate_risk_score(
        entropy=7.8,
        iocs={
            "urls": ["http://example.com"],
            "ips": ["192.0.2.1"],
            "domains": ["example.com"],
        },
        yara_matches=["Suspicious_Command"],
    )

    assert score == 9


def test_risk_score_maximum():
    """Le score ne dépasse jamais 10."""
    score = calculate_risk_score(
        entropy=8.0,
        iocs={
            "urls": ["http://example.com"],
            "ips": ["192.0.2.1"],
            "domains": ["example.com"],
        },
        yara_matches=["Rule1", "Rule2", "Rule3"],
    )

    assert score == 10