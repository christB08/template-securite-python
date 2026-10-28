import logging

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

        metadata = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        binary_info = sample.parse_binary()
        yara_matches = self.scanner.scan(sample.data)

        return {
            **metadata,
            "iocs": iocs,
            "imports": binary_info["imports"],
            "exports": binary_info["exports"],
            "sections": binary_info["sections"],
            "yara_matches": yara_matches,
            "family_guess": "unknown",
            "mitre_attack": [],
            "llm_summary": "Analyse statique locale, sans LLM.",
            "score": 0,
            "flag": None,
        }