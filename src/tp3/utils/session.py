"""Gestion de la session HTTP pour le challenge web."""

import requests

from tp3.utils.captcha import Captcha


class Session:
    """Gère le CAPTCHA et la récupération du premier drapeau."""

    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.http_session = requests.Session()
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.response = None
        self.data = {}

    def prepare_request(self) -> None:
        """Initialise la session et résout le CAPTCHA."""
        response = self.http_session.get(
            f"{self.url}/internal-panel",
            timeout=5,
        )
        response.raise_for_status()

        captcha = Captcha(
            f"{self.url}/captcha.png",
            self.http_session,
        )
        captcha.capture()
        captcha.solve()

        self.captcha_value = captcha.get_value()

    def submit_request(self) -> None:
        """Envoie la réponse du CAPTCHA au serveur."""
        self.response = self.http_session.post(
            f"{self.url}/internal-panel",
            data={"captcha": self.captcha_value},
            timeout=5,
        )

    def process_response(self) -> None:
        """Analyse la réponse du serveur."""
        if self.response is None:
            raise ValueError("Aucune réponse HTTP disponible")

        self.response.raise_for_status()

        self.data = self.response.json()
        self.valid_flag = self.data["flag1"]

    def get_flag(self) -> str:
        """Retourne le premier drapeau."""
        return self.valid_flag