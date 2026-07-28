import json
from datetime import datetime
from pathlib import Path

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)


class ReportGenerator:

    def __init__(self):

        self.report = {
            "tool": "AppSec Toolkit",
            "version": "1.0",
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": []
        }

    def add_finding(
        self,
        title,
        severity,
        description,
        recommendation,
        owasp,
        cwe
    ):

        self.report["findings"].append({

            "title": title,
            "severity": severity,
            "description": description,
            "recommendation": recommendation,
            "owasp": owasp,
            "cwe": cwe

        })

    def save_json(self):

        filename = REPORT_DIR / "report.json"

        with open(filename, "w", encoding="utf-8") as f:

            json.dump(
                self.report,
                f,
                indent=4
            )

        print(f"JSON Report Saved : {filename}")

    def save_markdown(self):

        filename = REPORT_DIR / "report.md"

        with open(filename, "w", encoding="utf-8") as f:

            f.write("# Application Security Report\n\n")

            f.write(
                f"Generated : {self.report['generated']}\n\n"
            )

            for finding in self.report["findings"]:

                f.write(f"## {finding['title']}\n\n")

                f.write(
                    f"**Severity** : {finding['severity']}\n\n"
                )

                f.write(
                    f"**OWASP** : {finding['owasp']}\n\n"
                )

                f.write(
                    f"**CWE** : {finding['cwe']}\n\n"
                )

                f.write(
                    f"### Description\n{finding['description']}\n\n"
                )

                f.write(
                    f"### Recommendation\n{finding['recommendation']}\n\n"
                )

                f.write("---\n\n")

        print(f"Markdown Report Saved : {filename}")

    def save_html(self):

        filename = REPORT_DIR / "report.html"

        html = f"""

<!DOCTYPE html>

<html>

<head>

<title>AppSec Report</title>

<style>

body{{font-family:Arial;background:#f5f5f5;margin:40px;}}

table{{border-collapse:collapse;width:100%;}}

th,td{{border:1px solid #ccc;padding:10px;}}

th{{background:#333;color:white;}}

.high{{color:red;font-weight:bold;}}

.medium{{color:orange;font-weight:bold;}}

.low{{color:green;font-weight:bold;}}

</style>

</head>

<body>

<h1>Application Security Report</h1>

<p><b>Generated:</b> {self.report["generated"]}</p>

<table>

<tr>

<th>Finding</th>

<th>Severity</th>

<th>OWASP</th>

<th>CWE</th>

<th>Description</th>

<th>Recommendation</th>

</tr>

"""

        for finding in self.report["findings"]:

            severity = finding["severity"].lower()

            html += f"""

<tr>

<td>{finding['title']}</td>

<td class="{severity}">
{finding['severity']}
</td>

<td>{finding['owasp']}</td>

<td>{finding['cwe']}</td>

<td>{finding['description']}</td>

<td>{finding['recommendation']}</td>

</tr>

"""

        html += """

</table>

</body>

</html>

"""

        with open(filename, "w", encoding="utf-8") as f:

            f.write(html)

        print(f"HTML Report Saved : {filename}")