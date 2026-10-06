import argparse
from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.detector import Detector
from tp1.utils.report import Report

def preflight_52f9be() -> None:
    """Initialise les vérifications nécessaires avant le lancement"""
    return None
def get_arguments() -> argparse.Namespace:
    """Récupère les arguments passés en ligne de commande"""
    parser = argparse.ArgumentParser(
        description="Analyse une capture réseau et détecte des attaques"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Chemin vers le fichier PCAP à analyser",
    )
    parser.add_argument(
        "--out",
        default="report.json",
        help="Fichier JSON de sortie",
    )

    return parser.parse_args()


def main () -> None:
    preflight_52f9be()
    args = get_arguments()

    capture = Capture()
    capture.read_pcap(args.pcap)

    protocols = capture.get_all_protocols()
    logger.info("protocols; detectés: %s",protocols)

    detector = Detector(capture.packets)
    port_scan_attacks = detector.detect_port_scan()
    logger.info("port_scan_attacks: %s",port_scan_attacks)

    arp_attacks = detector.detect_arp_spoofing()
    logger.info("arp_spoofing: %s",arp_attacks)

    sql_injection = detector.detect_sql_injection()
    logger.info("sql_injection: %s",sql_injection)

    logger.info("Starting TP1")
    logger.info("PCAP file: %s", args.pcap)
    logger.info("JSON report: %s", args.out)

if __name__== "__main__":
    main()