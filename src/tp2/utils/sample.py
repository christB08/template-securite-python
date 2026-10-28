import hashlib
import math
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

    def extract_iocs(self) -> dict:
        """Extrait les indicateurs de compromission"""
        raise NotImplementedError

    def parse_binary(self) -> dict:
        """Analyse les imports, exports et sections du binaire."""
        raise NotImplementedError