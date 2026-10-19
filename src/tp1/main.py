from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import generer_json
import argparse



def main():
    logger.info("Starting TP1")

    capture = Capture()
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    capture.lire_fichier_pcap(args.pcap)
    resulats_protocoles = capture.get_all_protocols()
    logger.info("Protocoles captures : %s", resulats_protocoles)
    attaques_arp = capture.detecter__arp_spoofing()
    logger.info("Attaques ARP detectees : %s", attaques_arp)
    alerte_arp = []
    for ip, ancienne_mac, nouvelle_mac in attaques_arp:
        alerte = {
            "type": "arp_spoofing",
            "attacker" : nouvelle_mac,
        }
        alerte_arp.append(alerte)
    capture.analyse("tcp")
    summary = capture.get_summary()

    attaques_syn = capture.detecter_scan_syn()
    attaques_sql = capture.detecter_injection_sql()
    flag = capture.extraire_flag()
    alertes = alerte_arp + attaques_syn + attaques_sql


    rapport = {
        "protocols": resulats_protocoles,
        "attacks": alertes,
        "flag": flag
    }
    
    generer_json(rapport, args.out)
if __name__ == "__main__":
    main()

