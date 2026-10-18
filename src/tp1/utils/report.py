from tp1.utils.capture import Capture
import json


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concatenate report content
        :return:
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        final_content = self.concat_report()
        with open(self.filename, "w") as report:
            report.write(final_content)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            # TODO: generate graph
            graph = ""
            self.graph = graph
        elif param == "array":
            # TODO: generate array
            array = ""
            self.array = array

def generer_json(rapport : dict, chemin : str) -> None:
    with open(chemin, "w", encoding="utf-8") as json_file:
        json.dump(rapport, json_file, indent=4)