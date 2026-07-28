import ssl
import socket
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()


def check_ssl(host):

    context = ssl.create_default_context()

    try:

        with socket.create_connection((host, 443), timeout=10) as sock:

            with context.wrap_socket(sock, server_hostname=host) as ssock:

                cert = ssock.getpeercert()

                protocol = ssock.version()

                cipher = ssock.cipher()

    except Exception as e:

        console.print(f"[red]Connection Failed:[/red] {e}")
        return

    table = Table(title=f"SSL/TLS Analysis - {host}")

    table.add_column("Property", style="cyan")
    table.add_column("Value")
    table.add_column("Status")

    expiry = datetime.strptime(
        cert["notAfter"],
        "%b %d %H:%M:%S %Y %Z"
    )

    days = (expiry - datetime.utcnow()).days

    subject = dict(x[0] for x in cert["subject"])
    issuer = dict(x[0] for x in cert["issuer"])

    table.add_row(
        "TLS Version",
        protocol,
        "OK" if protocol in ["TLSv1.2", "TLSv1.3"] else "Weak"
    )

    table.add_row(
        "Cipher",
        cipher[0],
        "OK"
    )

    table.add_row(
        "Issuer",
        issuer.get("organizationName", "Unknown"),
        "-"
    )

    table.add_row(
        "Common Name",
        subject.get("commonName", ""),
        "-"
    )

    table.add_row(
        "Expires",
        expiry.strftime("%Y-%m-%d"),
        "Valid" if days > 30 else "Expiring Soon"
    )

    table.add_row(
        "Days Remaining",
        str(days),
        "-"
    )

    console.print(table)

    console.print("\n[bold]Security Assessment[/bold]\n")

    if protocol in ["TLSv1", "TLSv1.1"]:
        console.print(
            "[red]- Deprecated TLS version detected."
        )

    if protocol == "TLSv1.3":
        console.print(
            "[green]- Latest TLS version in use."
        )

    elif protocol == "TLSv1.2":
        console.print(
            "[green]- TLS 1.2 is secure."
        )

    if days < 30:
        console.print(
            "[yellow]- Certificate expires within 30 days."
        )

    console.print(
        "\nOWASP Mapping : A02 Cryptographic Failures"
    )

    console.print(
        "CWE Mapping   : CWE-327"
    )