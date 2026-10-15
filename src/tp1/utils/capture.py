from tp1.utils.config import logger
from scapy.all import rdpcap
from scapy.all import PacketList
from scapy.all import TCP, UDP, ARP, ICMP, Ether, IP, DNS
from scapy.layers.http import HTTP



class Capture:
    def __init__(self) -> None:
            self.interface = None
            self.summary = ""
    

    def lire_fichier_pcap(self, chemin: str)-> None :
         """lire le fichier pcap et retourner la liste des paquets"""
         self.packets = rdpcap(chemin)
         logger.info("fichier a ete chargé avec succes : %d", len (self.packets))





    
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

    def get_all_protocols(self) -> dict[str, int]:

        """
        Return all protocols captured with total packets number"""

        protocoles = { "TCP": 0,
                      "UDP": 0,
                      "ARP": 0,
                      "ICMP": 0,
                      "ETHERNET": 0,
                      "IP": 0,
                      "DNS": 0,
                      "HTTP": 0
                      }

        for packet in self.packets:
            if TCP in packet:
                protocoles["TCP"] += 1
            if UDP in packet:
                protocoles["UDP"] += 1
            if ARP in packet:
                protocoles["ARP"] += 1
            if ICMP in packet:
                protocoles["ICMP"] += 1
            if Ether in packet:
                protocoles["Ethernet"] += 1
            if IP in packet:
                protocoles["IP"] += 1
            if DNS in packet:
                protocoles["DNS"] += 1
            if HTTP in packet:
                protocoles["HTTP"] += 1

        return protocoles

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
