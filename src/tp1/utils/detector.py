import ipaddress
from collections import defaultdict
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.packet import Raw
from tp1.utils.config import logger
from scapy.layers.http import HTTP,HTTPRequest
from urllib.parse import unquote


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


    def detect_arp_spoofing(self) -> list[dict[str, str]]:
        first_mac_by_ip: dict[str, str] = {}
        attacks = []
        for packet in self.packets:
            if ARP not in packet :
                continue

            ip_source = packet[ARP].psrc
            mac_source = packet[ARP].hwsrc
            if ip_source not in first_mac_by_ip:
                first_mac_by_ip[ip_source] = mac_source
            elif first_mac_by_ip[ip_source] != mac_source:
                attack = {

                        "type": "arp_spoofing",
                        "attacker": mac_source,
                }
                if attack not in attacks:
                    attacks.append(attack)

        return attacks

    def detect_sql_injection(self) -> list[dict[str, str]]:
        attacks = []
        for packet in self.packets:
            if HTTPRequest not in packet :
                continue

            payload = packet[HTTPRequest].Path.decode("utf-8")
            payload = unquote(payload)
            payload = payload.lower()

            sql_paterns = [
                "union select",
                "or 1=1",
            ]

            for pattern in sql_paterns:
                if pattern in payload:
                    if IP in packet:
                        source_ip = packet[IP].src
                        attack = {
                            "type": "sql_injection",
                            "attacker": source_ip,
                        }

                        if attack not in attacks:
                            attacks.append(attack)

        return attacks
