from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.snmp import SNMP

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import rdpcap


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []

    def read_pcap(self, pcap_chemin: str) -> None:
       """lit un fichier PCAP et conserve le paquets"""""
       self.packets = rdpcap(pcap_chemin)
       logger.info("%d paquets chargés depuis %s", len(self.packets),pcap_chemin)



    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        protocol_reseau = {"ethernet": 0,
                           "arp": 0,
                           "ip":0,
                           "tcp":0,
                           "udp":0,
                           "icmp":0,
                           "dns":0,
                           "http":0,
                  }
        for packet in self.packets:
            if Ether in packet:
                protocol_reseau["ethernet"] += 1
            if ARP in packet:
                protocol_reseau["arp"] += 1
            if IP in packet:
                protocol_reseau["ip"] += 1
            if TCP in packet:
                protocol_reseau["tcp"] += 1
            if UDP in packet:
                protocol_reseau["udp"] += 1
            if ICMP in packet:
                protocol_reseau["icmp"] += 1
            if DNS in packet:
                protocol_reseau["dns"] += 1
            if HTTP in packet:
                protocol_reseau["http"] += 1
            """if SNMP in packet:
                protocol_reseau["snmp"] += 1"""
        return protocol_reseau


    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
