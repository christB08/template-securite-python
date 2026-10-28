import argparse
import logging
from pathlib import Path

from tp2.utils.report import Report
from tp2.utils.triage import Triage

logger = logging.getLogger(__name__)


def main() -> None:
    """Analyse les échantillons d'un dossier et génère leurs rapports."""
    parser = argparse.ArgumentParser(
        description="TP2 - Triage statique de fichiers suspects"
    )

    parser.add_argument(
        "--samples",
        required=True,
        help="Dossier contenant les échantillons à analyser",
    )

    parser.add_argument(
        "--rules",
        required=True,
        help="Dossier contenant les règles YARA",
    )

    parser.add_argument(
        "--out",
        required=True,
        help="Dossier de destination des rapports",
    )

    args = parser.parse_args()

    samples_dir = Path(args.samples)
    rules_dir = Path(args.rules)
    output_dir = Path(args.out)

    if not samples_dir.is_dir():
        parser.error(
            f"Dossier des échantillons introuvable : {samples_dir}"
        )

    if not rules_dir.is_dir():
        parser.error(
            f"Dossier des règles YARA introuvable : {rules_dir}"
        )

    output_dir.mkdir(parents=True, exist_ok=True)

    sample_files = sorted(
        path for path in samples_dir.iterdir() if path.is_file()
    )

    if not sample_files:
        parser.error("Aucun échantillon trouvé dans le dossier.")

    for sample_path in sample_files:
        try:
            logger.info("Analyse de %s", sample_path.name)

            # 1. Analyse statique du fichier
            result = Triage(
                str(sample_path),
                str(rules_dir),
            ).run()

            # 2. Définition des chemins de sortie
            json_path = (
                output_dir / f"{sample_path.name}.triage.json"
            )

            pdf_path = (
                output_dir / f"{sample_path.name}.triage.pdf"
            )

            # 3. Création de l'objet Report
            report = Report(result)

            # 4. Génération du JSON
            report.generate_json(str(json_path))

            # 5. Génération du PDF
            report.generate_pdf(str(pdf_path))

            logger.info("Rapport JSON créé : %s", json_path)
            logger.info("Rapport PDF créé : %s", pdf_path)

        except (OSError, ValueError, RuntimeError) as exc:
            logger.error(
                "Échec de l'analyse de %s : %s",
                sample_path.name,
                exc,
            )


if __name__ == "__main__":
    main()