import jwt
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()


def decode_jwt(token):

    try:

        header = jwt.get_unverified_header(token)

        payload = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_aud": False
            }
        )

    except Exception as e:
        console.print(f"[red]Invalid JWT:[/red] {e}")
        return

    console.print("\n[bold cyan]JWT Header[/bold cyan]")
    console.print_json(json.dumps(header))

    console.print("\n[bold cyan]JWT Payload[/bold cyan]")
    console.print_json(json.dumps(payload))

    table = Table(title="JWT Security Assessment")

    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Severity")
    table.add_column("Recommendation")

    alg = header.get("alg", "")

    if alg.lower() == "none":

        table.add_row(
            "Algorithm",
            "[red]alg=none[/red]",
            "Critical",
            "Reject unsigned JWTs."
        )

    elif alg.upper() == "HS256":

        table.add_row(
            "Algorithm",
            "HS256",
            "Low",
            "Ensure a strong secret key is used."
        )

    elif alg.upper() in ["RS256", "ES256"]:

        table.add_row(
            "Algorithm",
            alg,
            "Good",
            "-"
        )

    else:

        table.add_row(
            "Algorithm",
            alg,
            "Review",
            "Verify that the algorithm is approved."
        )

    if "exp" in payload:

        exp = datetime.fromtimestamp(payload["exp"])

        if exp < datetime.now():

            table.add_row(
                "Expiration",
                "[red]Expired[/red]",
                "Medium",
                "Reject expired tokens."
            )

        else:

            table.add_row(
                "Expiration",
                "Valid",
                "-",
                "-"
            )

    else:

        table.add_row(
            "Expiration",
            "Missing",
            "Medium",
            "Include an expiration claim."
        )

    if "iss" not in payload:

        table.add_row(
            "Issuer",
            "Missing",
            "Low",
            "Include an issuer (iss) claim."
        )

    if "aud" not in payload:

        table.add_row(
            "Audience",
            "Missing",
            "Low",
            "Include an audience (aud) claim."
        )

    if "sub" not in payload:

        table.add_row(
            "Subject",
            "Missing",
            "Low",
            "Include a subject (sub) claim."
        )

    console.print(table)