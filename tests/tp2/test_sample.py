import hashlib

from tp2.utils.sample import Sample


def test_get_file_metadata(tmp_path):
    """ca verifie les métadonnées calculées sur un fichier de test."""
    path = tmp_path / "test.bin"
    data = b"hello world"
    path.write_bytes(data)

    sample = Sample(str(path))
    metadata = sample.get_file_metadata()

    assert metadata["sha256"] == hashlib.sha256(data).hexdigest()
    assert metadata["md5"] == hashlib.md5(data).hexdigest()
    assert metadata["size"] == len(data)
    assert metadata["file_type"]
    assert 0 <= metadata["entropy"] <= 8


def test_shannon_entropy(tmp_path):
    """ca vérifie que des octets identiques donnent une entropie nulle."""
    path = tmp_path / "test.bin"
    path.write_bytes(b"AAAAAAAAAA")

    sample = Sample(str(path))

    assert sample.shannon_entropy() == 0.0