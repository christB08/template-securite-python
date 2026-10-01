from collections import defaultdict

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class Detector:
    """Détecte les comportements suspects dans une liste de paquets"""

    def __init__(self, packets: list[Packet]) -> None:
        self.packets = packets

    def detect_port_scan(self, threshold: int =10) -> list[dict[str, str]]:
        """Détecte les IPS qui envoient des SYN vers plusieurs ports"""
        ports_by_ip: dict[str, set[int]] = defaultdict(set)

        for packet in self.packets:
            if IP not in packet or TCP not in packet:
                continue

            tcp = packet[TCP]

            #SYN present mais pas ACK: début d'une connecion tcp
            if tcp.flags.S and not tcp.flags.A:
                source_ip = packet[IP].src
                ports_by_ip[source_ip].add(tcp.dport)


        attacks = []

        for source_ip, ports in ports_by_ip.items():
            if len(ports) >= threshold:
                attacks.append(
                    {
                        "type": "port_scan",
                        "attacker": source_ip,
                    }
                )

        return attacks
