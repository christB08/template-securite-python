from tp1.utils.config import logger
from scapy.all import rdpcap
from scapy.all import PacketList
from scapy.all import TCP, UDP, ARP, ICMP, Ether, IP, DNS
from scapy.layers.http import HTTP, HTTPRequest
from scapy.packet import Raw 
from urllib.parse import unquote, urlparse, parse_qs, urlsplit
import re 




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
                if operation == 2: 
                    if ip not in association_ip_mac: 
                        association_ip_mac[ip] = {}
                    if mac not in association_ip_mac[ip]: 
                        association_ip_mac[ip][mac] = 0
                    association_ip_mac[ip][mac] += 1
                    if Ether in packet: 
                        logger.info("ARP REPLY : IP=%s | MAC_ARP =%s | MAC_ETHERNET=%s | IP_CIBLE=%s", ip, mac, packet[Ether].src, ip_rechercher)
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
        logger.info("association ip-mac: %s", association_ip_mac)
        for ip, addresses_mac in association_ip_mac.items():
            if len(addresses_mac) > 1:
                mac_suspecte = max(addresses_mac, key=addresses_mac.get)
                logger.warning("conflit ARP : IP=%s, MAC suspecte=%s", ip, mac_suspecte)
                attaque_detectee.append((ip, "", mac_suspecte))
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

    def detecter_injection_sql(self) -> list:
        attaques_detectees = []
        motifs_sql = ["or 1=1", "union select", "drop table", "insert into", "select * from", "'--"]
        for packet in self.packets : 
            if IP in packet and HTTPRequest in packet :
                ip_source = packet[IP].src
                url = packet[HTTPRequest].Path.decode("utf-8", errors="ignore")
                url = unquote(url).lower()
                logger.info("HTTP : source=%s, url=%s", ip_source, url) 
                for motif in motifs_sql :
                    if motif in url :
                        attaques_detectees.append({
                            "type": "sql_injection",
                            "attacker": ip_source,
                            "url": url,
                            "motif": motif
                        })
                        break
                        logger.warning("Injection SQL detectee : source=%s, url=%s, motif=%s", ip_source, url, motif)
        return attaques_detectees

    def extraire_flag(self) -> str:
        for numero, packet in enumerate(self.packets, start=1):
                if HTTPRequest in packet:
                    url = packet[HTTPRequest].Path.decode("utf-8", errors="ignore")
                    parametres = parse_qs(urlsplit(url).query)
                    for token in parametres.get("token", []):
                        token = unquote(token)
                        resultat = re.search(r"ESGI\{[^}]+\}", token)
                        if resultat:
                            flag = resultat.group(0)
                            logger.info("Flag trouve dans le paquet %d : %s", numero, flag)
                            return flag

        return ""
        