import logging

from tp2.utils.classification import classify_sample
from tp2.utils.risk import calculate_risk_score
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner

logger = logging.getLogger(__name__)


class Triage:
    """Regroupe les résultats de l'analyse statique d'un fichier."""

    def __init__(self, path: str, rules_path: str = "rules") -> None:
        self.path = path
        self.scanner = YaraScanner(rules_path)

    def run(self) -> dict:
        """Analyse un fichier sans l'exécuter."""
        sample = Sample(self.path)

        logger.info("Analyse de %s", self.path)

        # 1. Récupération des métadonnées
        metadata = sample.get_file_metadata()

        # 2. Extraction des indicateurs de compromission
        iocs = sample.extract_iocs()

        # 3. Analyse de la structure du binaire
        binary_info = sample.parse_binary()

        # 4. Analyse avec les règles YARA
        yara_matches = self.scanner.scan(sample.data)

        # 5. Calcul du score de risque
        score = calculate_risk_score(
            entropy=metadata["entropy"],
            iocs=iocs,
            yara_matches=yara_matches,
        )

        # 6. Classification et correspondance MITRE ATT&CK
        family_guess, mitre_attack = classify_sample(
            yara_matches=yara_matches,
            entropy=metadata["entropy"],
        )

        # 7. Construction du rapport d'analyse
        return {
            **metadata,
            "iocs": iocs,
            "imports": binary_info["imports"],
            "exports": binary_info["exports"],
            "sections": binary_info["sections"],
            "yara_matches": yara_matches,
            "family_guess": family_guess,
            "mitre_attack": mitre_attack,
            "llm_summary": "Analyse statique locale, sans LLM.",
            "score": score,
            "flag": sample.extract_flag(),
        }