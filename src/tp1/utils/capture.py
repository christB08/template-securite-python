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
                      "Ethernet": 0,
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

    def detecter__arp_spoofing (self) -> list : 
        """Detecter les attaques ARP Spoofing"""
        association_ip_mac = {}
        attaque_detectee = []
        request_arp =set()
        compteur_reponse_arp = {}
        for packet in self.packets: 
            if ARP in packet: 
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc
                operation = packet[ARP].op
                mac_destination = packet[ARP].hwdst 
                ip_rechercher = packet[ARP].pdst
                logger.info("ARP packet: ip=%s, mac=%s, operation=%s", ip, mac, operation)
                if ip not in association_ip_mac: 
                        association_ip_mac[ip] = mac
                elif mac != association_ip_mac[ip]: 
                        ancienne_mac = association_ip_mac[ip]
                        nouvelle_mac = mac
                        alerte = (ip, ancienne_mac, nouvelle_mac)
                        if alerte not in attaque_detectee:
                            attaque_detectee.append(alerte)
                if operation == 1:
                    request_arp.add((ip, ip_rechercher))
                    logger.info("requete arp memorise: %s", request_arp)
                if operation == 2 : 
                     compteur_reponse_arp[mac] = compteur_reponse_arp.get(mac, 0) + 1
                     couple_attendu = (ip_rechercher, ip)
                     if couple_attendu not in request_arp:
                          logger.warning("reponse arp potentiellement malicieuse: mac=%s, ip=%s", mac, ip)
                     logger.info("reponse arp: mac=%s, IP annonce=%s, ip cible=%s, mac cible=%s", mac, ip, ip_rechercher, mac_destination)
                     logger.info("nombre de reponses arp par mac: %s", compteur_reponse_arp)
        return attaque_detectee

    def detecter_scan_syn(self) -> list:
        """Detecter les scans SYN"""
        scans = {}
        attaques_detectees = []
        for packet in self.packets: 
             if IP in packet and TCP in packet: 
                ip_source = packet[IP].src
                port = packet[TCP].dport
                flags = packet[TCP].flags
                if flags & 0x02 and not flags & 0x10: 

                    if ip_source not in scans:
                        scans[ip_source] = []

                    if port not in scans[ip_source]:
                        scans[ip_source].append(port)

        logger.info("Scans SYN detectes: %s", scans)
        for ip_source, ports in scans.items():
            if len(ports) >= 5: 
                attaques_detectees.append({
                    "type": "port_scan",
                    "attacker": ip_source,
                })
        logger.info("Attaques detectees: %s", attaques_detectees)
        return attaques_detectees
                    