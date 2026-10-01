from scapy.layers.inet import IP, TCP

from src.tp1.utils.detector import Detector

def test_detect_port_scan():
    #Given
    packets = [
        IP(src="10.0.0.8", dst="10.0.0.10") / TCP(dport=80, flags="S"),
        IP(src="10.0.0.8", dst="10.0.0.10") / TCP(dport=443, flags="S"),
        IP(src="10.0.0.8", dst="10.0.0.10") / TCP(dport=22, flags="S"),
    ]

    detector = Detector(packets)

    #When
    attacks = detector.detect_port_scan(threshold=10)

    #When
    attacks = detector.detect_port_scan(threshold=10)

    #Then
    assert attacks == []