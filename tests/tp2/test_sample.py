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

def test_extract_iocs(tmp_path):
    """Vérifie l'extraction des principaux IOC."""
    path = tmp_path / "ioc_test.bin"

    path.write_bytes(
        b"http://control.example.test/gate "
        b"185.10.20.30 "
        b"Global\\TestMutex "
        b"HKCU\\Software\\Test\\Run "
        b"C:\\Users\\Public\\test.exe"
    )

    sample = Sample(str(path))
    iocs = sample.extract_iocs()

    assert "http://control.example.test/gate" in iocs["urls"]
    assert "185.10.20.30" in iocs["ips"]
    assert "control.example.test" in iocs["domains"]
    assert "Global\\TestMutex" in iocs["mutex"]
    assert "HKCU\\Software\\Test\\Run" in iocs["registry"]
    assert "C:\\Users\\Public\\test.exe" in iocs["paths"]


def test_extract_iocs_invalid_ip(tmp_path):
    """Vérifie qu'une adresse IP invalide est rejetée."""
    path = tmp_path / "invalid_ip.bin"
    path.write_bytes(b"999.999.999.999")

    sample = Sample(str(path))
    iocs = sample.extract_iocs()

    assert iocs["ips"] == []