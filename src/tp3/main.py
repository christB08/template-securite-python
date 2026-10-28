"""TP3 - Breach the target (squelette).

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse

from tp3.utils.config import logger
from pathlib import Path
import requests 
from tp3.utils.session import Session



def fuzz_endpoints(target: str) -> list[str]:
    """Recherche un endpoint contenant un formulaire CAPTCHA."""

    wordlist_path = Path(__file__).parent / "wordlist.txt"

    with wordlist_path.open(encoding="utf-8") as file:
        chemins = [
            line.strip()
            for line in file
            if line.strip() and not line.startswith("#")
        ]

    compteur = 0

    for path in chemins:
        url = f"{target.rstrip('/')}/{path.lstrip('/')}"

        try:
            response = requests.get(url, timeout=2)
            compteur += 1

            if response.status_code == 200:
                if 'name="captcha"' in response.text:
                    logger.info("Endpoint CAPTCHA trouvé : %s", url)
                    logger.info("Requêtes effectuées : %d", compteur)
                    return [url]

        except requests.RequestException as error:
            logger.warning("Erreur sur %s : %s", url, error)

    logger.warning("Aucun endpoint CAPTCHA découvert")
    return []



def breach_web(target: str) -> tuple[str, int, bytes]:
    """Découvre le portail, résout le CAPTCHA et récupère Flag 1."""

    endpoints = fuzz_endpoints(target)

    for endpoint in endpoints:
        if endpoint:
            session = Session(target)

            for tentative in range(5):
                try:
                    session.prepare_request()
                    session.submit_request()
                    session.process_response()

                    logger.info("FLAG1: %s", session.get_flag())

                    host = session.data["host"]
                    port = int(session.data["port"])
                    key = bytes.fromhex(session.data["key"])

                    return host, port, key

                except requests.RequestException as error:
                    logger.warning(
                        "Tentative CAPTCHA %d échouée : %s",
                        tentative + 1,
                        error,
                    )

    raise RuntimeError("Impossible de récupérer le premier drapeau")


def breach_network(host: str, port: int, key: bytes) -> str:
    """pwntools/socket : décode le flux base64+XOR en boucle sous 30 s.

    Retourne le flag final. Indices : pwn.remote, base64.
    """
    raise NotImplementedError


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
