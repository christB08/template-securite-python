import json
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos


class Report:
    """Génère les rapports d'analyse statique aux formats JSON et PDF."""

    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_json(self, out_json: str) -> None:
        """Enregistre les résultats au format JSON."""
        output = Path(out_json)
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w", encoding="utf-8") as file:
            json.dump(
                self.result,
                file,
                indent=4,
                ensure_ascii=False,
            )

    def generate_pdf(self, out_pdf: str) -> None:
        """Génère un rapport PDF sans exécuter le fichier analysé."""
        output = Path(out_pdf)
        output.parent.mkdir(parents=True, exist_ok=True)

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        def safe_text(value: object) -> str:
            """Convertit une valeur en texte compatible avec Helvetica."""
            return (
                str(value)
                .encode("latin-1", errors="replace")
                .decode("latin-1")
            )

        def write_line(
            text: str,
            font_size: int = 10,
            bold: bool = False,
        ) -> None:
            """Écrit un texte et revient à la marge gauche."""
            pdf.set_font(
                "Helvetica",
                "B" if bold else "",
                font_size,
            )

            pdf.multi_cell(
                0,
                7,
                safe_text(text),
                new_x=XPos.LMARGIN,
                new_y=YPos.NEXT,
                wrapmode="CHAR",
            )

        def write_section(title: str) -> None:
            """Ajoute un titre de section."""
            pdf.ln(5)
            write_line(title, font_size=12, bold=True)

        # 1. Titre du rapport
        write_line(
            "Rapport d'analyse statique - TP2",
            font_size=18,
            bold=True,
        )

        write_line(
            "Analyse automatisée de malware - ESGI",
            font_size=10,
        )

        # 2. Informations générales
        write_section("1. Informations du fichier")

        fields = {
            "SHA-256": self.result.get("sha256", ""),
            "MD5": self.result.get("md5", ""),
            "Taille (octets)": self.result.get("size", ""),
            "Type de fichier": self.result.get("file_type", ""),
            "Entropie": self.result.get("entropy", ""),
            "Score de risque": f"{self.result.get('score', 0)}/10",
            "Famille probable": self.result.get(
                "family_guess",
                "unknown",
            ),
            "Flag": self.result.get("flag") or "Non trouve",
        }

        for label, value in fields.items():
            write_line(f"{label} : {value}")

        # 3. Résultats YARA
        write_section("2. Correspondances YARA")

        yara_matches = self.result.get("yara_matches", [])

        if yara_matches:
            for match in yara_matches:
                write_line(f"- {match}")
        else:
            write_line("Aucune correspondance YARA.")

        # 4. Techniques MITRE ATT&CK
        write_section("3. Techniques MITRE ATT&CK")

        mitre_attack = self.result.get("mitre_attack", [])

        if mitre_attack:
            for technique in mitre_attack:
                write_line(f"- {technique}")
        else:
            write_line("Aucune technique identifiee.")

        # 5. Indicateurs de compromission
        write_section("4. Indicateurs de compromission (IOC)")

        iocs = self.result.get("iocs", {})

        for category, values in iocs.items():
            write_line(
                category.upper(),
                font_size=10,
                bold=True,
            )

            if values:
                for value in values:
                    write_line(
                        f"- {value}",
                        font_size=9,
                    )
            else:
                write_line(
                    "Aucun indicateur.",
                    font_size=9,
                )

        # 6. Imports
        write_section("5. Fonctions importées")

        imports = self.result.get("imports", [])

        if imports:
            for imported_function in imports[:30]:
                write_line(
                    f"- {imported_function}",
                    font_size=9,
                )

            if len(imports) > 30:
                write_line(
                    f"... et {len(imports) - 30} autres imports."
                )
        else:
            write_line("Aucun import identifie.")

        # 7. Sections du binaire
        write_section("6. Sections du binaire")

        sections = self.result.get("sections", [])

        if sections:
            for section in sections:
                write_line(
                    f"- {section}",
                    font_size=9,
                )
        else:
            write_line("Aucune section identifiee.")

        # 8. Résumé de l'analyse
        write_section("7. Résumé de l'analyse")

        summary = self.result.get(
            "llm_summary",
            "Analyse statique locale, sans LLM.",
        )

        write_line(summary)

        # 9. Avertissement
        write_section("8. Limites de l'analyse")

        write_line(
            "Ce rapport repose sur une analyse statique. "
            "Les correspondances YARA, les classifications et "
            "les techniques MITRE sont des indices, "
            "pas des preuves de comportement malveillant."
        )

        # 10. Enregistrement du PDF
        pdf.output(str(output))