import json
from pathlib import Path


class Report:
    """Génère les rapports d'analyse."""

    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_json(self, out_json: str) -> None:
        """Enregistre les résultats dans un fichier JSON."""
        output = Path(out_json)
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w", encoding="utf-8") as file:
            json.dump(self.result, file, indent=4, ensure_ascii=False)

    def generate_pdf(self, out_pdf: str) -> None:
        """Génère un rapport PDF (à implémenter)."""
        raise NotImplementedError