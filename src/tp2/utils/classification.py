def classify_sample(
    yara_matches: list[str],
    entropy: float,
) -> tuple[str, list[str]]:
    """Propose une catégorie et des techniques MITRE à partir des indices."""
    matches = set(yara_matches)
    techniques = []

    if "Potential_C2_Communication" in matches:
        techniques.append("T1071.001")

    if "Suspicious_Windows_Persistence" in matches:
        techniques.append("T1547.001")

    if "Potential_Keylogging_Indicators" in matches:
        techniques.append("T1056.001")

    if "Suspicious_Shell_Command" in matches:
        techniques.append("T1059")

    if "Potential_Keylogging_Indicators" in matches:
        family = "potential_keylogger"
    elif entropy >= 7.0:
        family = "potential_packed"
    elif "Potential_C2_Communication" in matches:
        family = "potential_backdoor"
    else:
        family = "unknown"

    return family, techniques