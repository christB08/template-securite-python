def generate_local_summary(
    family_guess: str,
    score: int,
    yara_matches: list[str],
    mitre_attack: list[str],
) -> str:
    """Produit un résumé déterministe à partir des indices statiques."""

    descriptions = {
        "potential_keylogger": "des indicateurs potentiels de capture clavier",
        "potential_backdoor": "des indicateurs potentiels de communication C2",
        "potential_packed": "une entropie élevée pouvant évoquer un empaquetage",
        "unknown": "aucune famille clairement identifiable",
    }

    description = descriptions.get(
        family_guess,
        "un comportement non classifié",
    )

    yara_text = (
        ", ".join(yara_matches)
        if yara_matches
        else "aucune correspondance"
    )

    mitre_text = (
        ", ".join(mitre_attack)
        if mitre_attack
        else "aucune technique associée"
    )

    return (
        f"L'analyse statique révèle {description}. "
        f"Le score de risque heuristique est de {score}/10. "
        f"Règles YARA détectées : {yara_text}. "
        f"Techniques MITRE ATT&CK associées : {mitre_text}. "
        "Ces observations ne prouvent pas l'exécution "
        "d'un comportement malveillant."
    )