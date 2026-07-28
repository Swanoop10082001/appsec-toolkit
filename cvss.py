from rich.console import Console
from rich.table import Table

console = Console()

AV = {
    "N": 0.85,
    "A": 0.62,
    "L": 0.55,
    "P": 0.20
}

AC = {
    "L": 0.77,
    "H": 0.44
}

PR_U = {
    "N": 0.85,
    "L": 0.62,
    "H": 0.27
}

PR_C = {
    "N": 0.85,
    "L": 0.68,
    "H": 0.50
}

UI = {
    "N": 0.85,
    "R": 0.62
}

CIA = {
    "H": 0.56,
    "L": 0.22,
    "N": 0.00
}


def severity(score):

    if score == 0:
        return "None"

    elif score <= 3.9:
        return "Low"

    elif score <= 6.9:
        return "Medium"

    elif score <= 8.9:
        return "High"

    return "Critical"


def parse_vector(vector):

    metrics = {}

    vector = vector.replace("CVSS:3.1/", "")

    for item in vector.split("/"):
        key, value = item.split(":")
        metrics[key] = value

    return metrics


def calculate_cvss(vector):

    try:

        metrics = parse_vector(vector)

    except Exception:

        console.print("[red]Invalid CVSS Vector[/red]")
        return

    scope = metrics["S"]

    av = AV[metrics["AV"]]
    ac = AC[metrics["AC"]]

    if scope == "U":
        pr = PR_U[metrics["PR"]]
    else:
        pr = PR_C[metrics["PR"]]

    ui = UI[metrics["UI"]]

    c = CIA[metrics["C"]]
    i = CIA[metrics["I"]]
    a = CIA[metrics["A"]]

    isc = 1 - ((1 - c) * (1 - i) * (1 - a))

    impact = 6.42 * isc

    exploitability = 8.22 * av * ac * pr * ui

    score = min(round(impact + exploitability, 1), 10)

    table = Table(title="CVSS v3.1 Base Score")

    table.add_column("Metric")
    table.add_column("Value")

    table.add_row("Vector", vector)
    table.add_row("Attack Vector", metrics["AV"])
    table.add_row("Attack Complexity", metrics["AC"])
    table.add_row("Privileges Required", metrics["PR"])
    table.add_row("User Interaction", metrics["UI"])
    table.add_row("Scope", metrics["S"])
    table.add_row("Confidentiality", metrics["C"])
    table.add_row("Integrity", metrics["I"])
    table.add_row("Availability", metrics["A"])

    table.add_row("Base Score", str(score))
    table.add_row("Severity", severity(score))

    console.print(table)
