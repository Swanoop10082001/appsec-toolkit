import requests
from rich.console import Console
from rich.table import Table

console = Console()

RISKY_METHODS = {
    "PUT": {
        "severity": "High",
        "reason": "May allow resource creation or modification."
    },
    "DELETE": {
        "severity": "High",
        "reason": "May allow resource deletion."
    },
    "TRACE": {
        "severity": "High",
        "reason": "Can enable Cross-Site Tracing (XST)."
    },
    "CONNECT": {
        "severity": "High",
        "reason": "May allow proxy tunnelling."
    },
    "PATCH": {
        "severity": "Medium",
        "reason": "Allows partial resource modification."
    }
}


def check_methods(url):

    console.print(f"\n[bold cyan]Testing HTTP Methods[/bold cyan]")
    console.print(f"Target : {url}\n")

    methods = [
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "OPTIONS",
        "HEAD",
        "TRACE",
        "PATCH",
        "CONNECT"
    ]

    table = Table(title="HTTP Method Enumeration")

    table.add_column("Method")
    table.add_column("Status Code")
    table.add_column("Supported")
    table.add_column("Severity")
    table.add_column("Remarks")

    supported = []

    for method in methods:

        try:

            response = requests.request(
                method,
                url,
                timeout=5,
                allow_redirects=False
            )

            code = response.status_code

            if code not in [404, 405, 501]:

                supported.append(method)

                if method in RISKY_METHODS:

                    table.add_row(
                        method,
                        str(code),
                        "[green]Yes[/green]",
                        RISKY_METHODS[method]["severity"],
                        RISKY_METHODS[method]["reason"]
                    )

                else:

                    table.add_row(
                        method,
                        str(code),
                        "[green]Yes[/green]",
                        "-",
                        "-"
                    )

            else:

                table.add_row(
                    method,
                    str(code),
                    "[red]No[/red]",
                    "-",
                    "-"
                )

        except Exception:

            table.add_row(
                method,
                "Error",
                "-",
                "-",
                "Connection Failed"
            )

    console.print(table)

    console.print("\n[bold yellow]Summary[/bold yellow]")

    console.print(
        f"Supported Methods : {', '.join(supported)}"
    )

    dangerous = [
        m for m in supported if m in RISKY_METHODS
    ]

    if dangerous:

        console.print(
            f"[red]Risky Methods Detected : {', '.join(dangerous)}[/red]"
        )

    else:

        console.print(
            "[green]No risky HTTP methods detected.[/green]"
        )

    console.print("\nOWASP Top 10")
    console.print("A05:2021 - Security Misconfiguration")

    console.print("\nCWE")
    console.print("CWE-650 - Trusting HTTP Permission Methods")