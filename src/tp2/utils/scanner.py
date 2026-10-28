import logging
from pathlib import Path

import yara

logger = logging.getLogger(__name__)


class YaraScanner:
    """Analyse des données avec des règles YARA."""

    def __init__(self, rules_path: str = "rules") -> None:
        self.rules_path = Path(rules_path)

    def scan(self, data: bytes) -> list[str]:
        """Retourne les noms des règles correspondant aux données."""
        if not self.rules_path.exists():
            logger.warning("Chemin des règles introuvable : %s", self.rules_path)
            return []

        if self.rules_path.is_file():
            rule_files = [self.rules_path]
        else:
            rule_files = sorted(
                [
                    path
                    for path in self.rules_path.rglob("*")
                    if path.is_file() and path.suffix.lower() in {".yar", ".yara"}
                ]
            )

        if not rule_files:
            logger.warning("Aucune règle YARA trouvée dans %s", self.rules_path)
            return []

        matches: set[str] = set()

        for rule_file in rule_files:
            try:
                rules = yara.compile(filepath=str(rule_file))
                results = rules.match(data=data)

                for match in results:
                    matches.add(match.rule)

            except yara.Error as exc:
                logger.warning(
                    "Impossible d'utiliser la règle %s : %s",
                    rule_file,
                    exc,
                )

        return sorted(matches)