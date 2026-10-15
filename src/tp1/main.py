from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report
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
    capture.analyse("tcp")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
