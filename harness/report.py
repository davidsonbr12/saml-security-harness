import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SEVERITY_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#2980b9",
    "INFO":     "#7f8c8d",
}

_STATUS_COLOR = {
    "PASS": "#27ae60",
    "FAIL": "#c0392b",
    "WARN": "#e67e22",
}


@dataclass
class ReportFinding:
    test_name: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    status:   Literal["PASS", "FAIL", "WARN"]
    detail: str
    remediation: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))


def generate_json_report(findings: list[ReportFinding], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    counts = {s: 0 for s in SEVERITY_ORDER}
    status_counts = {"PASS": 0, "FAIL": 0, "WARN": 0}
    for f in findings:
        counts[f.severity] += 1
        status_counts[f.status] += 1

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"total": len(findings), "by_severity": counts, "by_status": status_counts},
        "findings": [
            {
                "id": f.id,
                "test_name": f.test_name,
                "severity": f.severity,
                "status": f.status,
                "detail": f.detail,
                "remediation": f.remediation,
            }
            for f in findings
        ],
    }

    Path(output_path).write_text(json.dumps(payload, indent=2))


def generate_html_report(findings: list[ReportFinding], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
    status_counts = {s: sum(1 for f in findings if f.status == s) for s in ["PASS", "FAIL", "WARN"]}
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    summary_chips = "".join(
        f'<span style="background:{_SEVERITY_COLOR[s]};color:#fff;padding:4px 12px;'
        f'border-radius:12px;margin:0 4px;font-weight:bold;">'
        f'{counts[s]} {s}</span>'
        for s in SEVERITY_ORDER
    )

    status_chips = "".join(
        f'<span style="background:{_STATUS_COLOR[s]};color:#fff;padding:4px 12px;'
        f'border-radius:12px;margin:0 4px;font-weight:bold;">'
        f'{status_counts[s]} {s}</span>'
        for s in ["PASS", "FAIL", "WARN"]
    )

    rows = "".join(
        f'<tr>'
        f'<td style="font-family:monospace;font-size:0.85em;color:#555">{f.test_name}</td>'
        f'<td><span style="background:{_SEVERITY_COLOR[f.severity]};color:#fff;'
        f'padding:2px 10px;border-radius:10px;font-weight:bold">{f.severity}</span></td>'
        f'<td><span style="background:{_STATUS_COLOR[f.status]};color:#fff;'
        f'padding:2px 10px;border-radius:10px;font-weight:bold">{f.status}</span></td>'
        f'<td>{f.detail}</td>'
        f'<td style="color:#555;font-size:0.9em">{f.remediation}</td>'
        f'</tr>'
        for f in sorted_findings
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SAML Security Report</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           margin: 0; padding: 24px; background: #f5f6fa; color: #2c3e50; }}
    h1   {{ margin: 0 0 4px; font-size: 1.6em; }}
    .meta {{ color: #7f8c8d; font-size: 0.9em; margin-bottom: 20px; }}
    .summary {{ background: #fff; border-radius: 8px; padding: 16px 20px;
                margin-bottom: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    .summary h2 {{ margin: 0 0 10px; font-size: 1em; color: #7f8c8d;
                   text-transform: uppercase; letter-spacing: .05em; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff;
             border-radius: 8px; overflow: hidden;
             box-shadow: 0 1px 4px rgba(0,0,0,.08); }}
    th    {{ background: #2c3e50; color: #fff; padding: 10px 14px;
             text-align: left; font-size: 0.85em; text-transform: uppercase;
             letter-spacing: .05em; cursor: pointer; user-select: none; }}
    th:hover {{ background: #34495e; }}
    td    {{ padding: 10px 14px; border-bottom: 1px solid #ecf0f1;
             vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #f8f9fa; }}
  </style>
</head>
<body>
  <h1>SAML Security Test Report</h1>
  <p class="meta">Generated {timestamp} &nbsp;·&nbsp; {len(findings)} findings</p>

  <div class="summary">
    <h2>By Severity</h2>
    <div>{summary_chips}</div>
  </div>
  <div class="summary">
    <h2>By Status</h2>
    <div>{status_chips}</div>
  </div>

  <table id="findings-table">
    <thead>
      <tr>
        <th onclick="sortTable(0)">Test ↕</th>
        <th onclick="sortTable(1)">Severity ↕</th>
        <th onclick="sortTable(2)">Status ↕</th>
        <th onclick="sortTable(3)">Detail ↕</th>
        <th onclick="sortTable(4)">Remediation ↕</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>

  <script>
    function sortTable(col) {{
      const table = document.getElementById("findings-table");
      const tbody = table.tBodies[0];
      const rows  = Array.from(tbody.rows);
      const asc   = table.dataset.sortCol == col && table.dataset.sortDir === "asc";
      rows.sort((a, b) => {{
        const x = a.cells[col].innerText;
        const y = b.cells[col].innerText;
        return asc ? y.localeCompare(x) : x.localeCompare(y);
      }});
      rows.forEach(r => tbody.appendChild(r));
      table.dataset.sortCol = col;
      table.dataset.sortDir = asc ? "desc" : "asc";
    }}
  </script>
</body>
</html>"""

    Path(output_path).write_text(html)
