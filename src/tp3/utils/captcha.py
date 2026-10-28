from io import BytesIO

import pytesseract
import requests
from PIL import Image, ImageEnhance, ImageOps


class Captcha:
    def __init__(self, url: str, session: requests.Session | None = None):
        self.url = url
        self.session = session if session is not None else requests.Session()
        self.image = None
        self.value = ""

    def capture(self) -> None:
        """Télécharge le CAPTCHA avec la session HTTP existante."""
        response = self.session.get(self.url, timeout=5)
        response.raise_for_status()

        self.image = Image.open(BytesIO(response.content)).convert("RGB")

    def solve(self) -> None:
        """Reconnaît les caractères du CAPTCHA."""
        if self.image is None:
            raise ValueError("Aucune image CAPTCHA disponible")

        image = ImageOps.grayscale(self.image)
        image = ImageEnhance.Contrast(image).enhance(2)
        image = image.point(lambda pixel: 255 if pixel > 160 else 0)

        self.value = pytesseract.image_to_string(
            image,
            config="--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        ).strip()

    def get_value(self) -> str:
        """Retourne la valeur reconnue."""
        return self.value