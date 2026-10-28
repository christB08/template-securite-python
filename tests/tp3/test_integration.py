"""Tests du fonctionnement du TP3 sur la cible locale."""

from tp3.main import breach_web, breach_network


def test_breach_web():
    """Vérifie la récupération des paramètres TCP après le CAPTCHA."""
    host, port, key = breach_web("http://127.0.0.1:8080")

    assert isinstance(host, str)
    assert isinstance(port, int)
    assert isinstance(key, bytes)
    assert len(key) > 0


def test_breach_network():
    """Vérifie la récupération du flag final."""
    host, port, key = breach_web("http://127.0.0.1:8080")

    flag = breach_network(host, port, key)

    assert flag.startswith("ESGI{")
    assert flag.endswith("}")
