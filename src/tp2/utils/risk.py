def calculate_risk_score(
    entropy: float,
    iocs: dict[str, list[str]],
    yara_matches: list[str],
) -> int:
    """Calcule un score de risque indicatif entre 0 et 10."""
    score = 0

    # Une entropie élevée peut signaler du contenu compressé ou chiffré.
    if entropy >= 7.5:
        score += 3
    elif entropy >= 7.0:
        score += 2

    # Les indicateurs réseau contribuent au score.
    if iocs.get("urls"):
        score += 2

    if iocs.get("ips"):
        score += 1

    if iocs.get("domains"):
        score += 1

    # Les règles YARA apportent des indices supplémentaires.
    score += min(len(yara_matches) * 2, 4)

    return min(score, 10)