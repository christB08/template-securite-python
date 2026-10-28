import hashlib
import ipaddress
import math
import re
from collections import Counter
from pathlib import Path

import magic


class Sample:
    """ la ca represente un fichier à analyser sans vraiment l'executer"""

    def __init__(self, path: str) -> None:
        self.path = path
        self.data = Path(path).read_bytes()

    def get_file_metadata(self) -> dict:
        """la ca calcule tout ce qui est empreintes et taille et le type et l'entropi"""
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "file_type": magic.from_buffer(self.data),
            "entropy": round(self.shannon_entropy(), 2),
        }

    def shannon_entropy(self) -> float:
        """la ca calcule l'entropie de Shannon des octets du fichier."""
        if not self.data:
            return 0.0

        freq = Counter(self.data)
        n = len(self.data)

        return -sum(
            (count / n) * math.log2(count / n)
            for count in freq.values()
        )

    def extract_iocs(self) -> dict[str, list[str]]:
        """la ca va extraire les IOC présents dans les chaînes du fichier."""
        text = self.data.decode("latin-1", errors="ignore")

        patterns = {
            "urls": r"https?://[^\s\"'<>]+",
            "ips": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "domains": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
            "mutex": r"(?:Global|Local)\\[A-Za-z0-9_.-]+",
            "registry": (
    r"(?:HKCU|HKLM|HKEY_CURRENT_USER|HKEY_LOCAL_MACHINE)"
    r"\\[A-Za-z0-9_\\.-]+"
),
            "paths": r"[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+",
        }

        results: dict[str, list[str]] = {}

        for category, pattern in patterns.items():
            matches = re.findall(pattern, text)

            if category == "ips":
                valid_ips = []
                for value in matches:
                    try:
                        ipaddress.ip_address(value)
                        valid_ips.append(value)
                    except ValueError:
                        continue
                matches = valid_ips

            results[category] = sorted(set(matches))

        return results

    def parse_binary(self) -> dict:
        """Analyse les imports, exports et sections du binaire."""
        raise NotImplementedError