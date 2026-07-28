import math
import re
from rich.console import Console
from rich.table import Table

console = Console()

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "admin",
    "welcome",
    "letmein",
    "abc123",
    "iloveyou"
}


def calculate_entropy(password):

    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26

    if re.search(r"[A-Z]", password):
        charset += 26

    if re.search(r"[0-9]", password):
        charset += 10

    if re.search(r"[^A-Za-z0-9]", password):
        charset += 32

    if charset == 0:
        return 0

    return round(len(password) * math.log2(charset), 2)


def check_password(password):

    table = Table(title="Password Strength Assessment")

    table.add_column("Property", style="cyan")
    table.add_column("Value")

    score = 0

    issues = []

    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        issues.append("Password should be at least 12 characters.")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        issues.append("Missing uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        issues.append("Missing lowercase letter.")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        issues.append("Missing numeric digit.")

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    else:
        issues.append("Missing special character.")

    entropy = calculate_entropy(password)

    if password.lower() in COMMON_PASSWORDS:
        score = 0
        issues.append("Password appears in a list of common passwords.")

    if score <= 2:
        rating = "Weak"
        colour = "red"

    elif score <= 4:
        rating = "Moderate"
        colour = "yellow"

    elif score <= 6:
        rating = "Strong"
        colour = "green"

    else:
        rating = "Very Strong"
        colour = "green"

    table.add_row("Length", str(len(password)))
    table.add_row("Entropy", f"{entropy} bits")
    table.add_row("Strength", f"[{colour}]{rating}[/{colour}]")
    table.add_row("Score", f"{score}/6")

    console.print(table)

    if issues:

        console.print("\n[bold yellow]Recommendations[/bold yellow]\n")

        for issue in issues:
            console.print(f"- {issue}")

    else:

        console.print(
            "\n[bold green]Password meets recommended complexity requirements.[/bold green]"
        )

    console.print("\nOWASP Mapping")
    console.print("A07:2021 - Identification and Authentication Failures")

    console.print("\nCWE Mapping")
    console.print("CWE-521 - Weak Password Requirements")