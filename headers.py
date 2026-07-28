import requests
from rich.console import Console
from rich.table import Table

console = Console()

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "High",
        "recommendation": "Enable HSTS to force HTTPS connections.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-319"
    },
    "Content-Security-Policy": {
        "severity": "High",
        "recommendation": "Define a Content Security Policy to reduce XSS attacks.",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79"
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN.",
        "owasp": "A05:2021",
        "cwe": "CWE-1021"
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "recommendation": "Set X-Content-Type-Options: nosniff.",
        "owasp": "A05:2021",
        "cwe": "CWE-16"
    },
    "Referrer-Policy": {
        "severity": "Low",
        "recommendation": "Configure Referrer-Policy appropriately.",
        "owasp": "A05:2021",
        "cwe": "CWE-200"
    },
    "Permissions-Policy": {
        "severity": "Low",
        "recommendation": "Restrict unnecessary browser features.",
        "owasp": "A05:2021",
        "cwe": "CWE-16"
    }
}


def check_headers(url):

    try:
        response = requests.get(url, timeout=10)

    except Exception as e:
        console.print(f"[red]Connection Error[/red]: {e}")
        return

    table = Table(title="HTTP Security Headers")

    table.add_column("Header", style="cyan")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("OWASP")
    table.add_column("CWE")

    missing = []

    for header, info in SECURITY_HEADERS.items():

        if header in response.headers:

            table.add_row(
                header,
                "[green]Present[/green]",
                "-",
                "-",
                "-"
            )

        else:

            missing.append(header)

            table.add_row(
                header,
                "[red]Missing[/red]",
                info["severity"],
                info["owasp"],
                info["cwe"]
            )

    console.print(table)

    if len(missing) == 0:
        console.print("\n[bold green]No missing security headers detected.[/bold green]")
    else:
        console.print("\n[bold yellow]Recommendations[/bold yellow]\n")

        for h in missing:
            console.print(f"[red]{h}[/red]")
            console.print(f"  → {SECURITY_HEADERS[h]['recommendation']}\n")
