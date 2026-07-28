import base64
import re
from rich.console import Console
from rich.table import Table

console = Console()


def is_base64(value):
    pattern = r'^[A-Za-z0-9+/=_-]+$'

    if len(value) % 4 != 0:
        return False

    return re.match(pattern, value) is not None


def encode_base64(text):

    encoded = base64.b64encode(text.encode()).decode()

    table = Table(title="Base64 Encoding")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    table.add_row("Input", text)
    table.add_row("Encoded", encoded)

    console.print(table)


def decode_base64(value):

    table = Table(title="Base64 Decoding")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    try:

        if not is_base64(value):

            console.print("[red]Input does not appear to be valid Base64.[/red]")
            return

        decoded = base64.b64decode(value).decode("utf-8")

        table.add_row("Input", value)
        table.add_row("Decoded", decoded)

        console.print(table)

        analyse_decoded(decoded)

    except UnicodeDecodeError:

        decoded = base64.b64decode(value)

        table.add_row("Input", value)
        table.add_row("Decoded", decoded.hex())

        console.print(table)

        console.print(
            "\n[yellow]Binary data detected.[/yellow]"
        )

    except Exception as e:

        console.print(f"[red]Decode Failed:[/red] {e}")


def analyse_decoded(text):

    console.print("\n[bold cyan]Content Analysis[/bold cyan]\n")

    if text.startswith("{") and text.endswith("}"):

        console.print("[green]JSON detected[/green]")

    elif text.startswith("<"):

        console.print("[green]XML/HTML detected[/green]")

    elif "." in text and len(text.split(".")) == 3:

        console.print("[yellow]Possible JWT detected[/yellow]")

    elif "http://" in text or "https://" in text:

        console.print("[green]URL detected[/green]")

    else:

        console.print("Plain text detected")
