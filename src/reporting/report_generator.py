"""CHG-027 — HTML Dashboard Generator.

Reads pipeline artifacts and produces a self-contained HTML report.

Usage
-----
    python -m src.reporting.report_generator --artifacts artifacts/ --output artifacts/dashboard.html
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# CSS / HTML constants
# ---------------------------------------------------------------------------

_CSS = """
:root {
  --bg:       #0a0e1a;
  --surface:  #131929;
  --border:   #1e2d4a;
  --accent:   #00d4ff;
  --text:     #c8d6e5;
  --muted:    #5a7a9a;
  --critical: #ff3b5c;
  --high:     #ff8c42;
  --medium:   #ffd166;
  --low:      #06d6a0;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
       font-size: 14px; min-height: 100vh; padding: 0 0 40px; }
header { background: var(--surface); border-bottom: 1px solid var(--border);
         padding: 18px 32px; display: flex; align-items: center; gap: 12px; }
header h1 { font-size: 20px; color: var(--accent); letter-spacing: 0.5px; }
header span { font-size: 12px; color: var(--muted); margin-left: auto; }
.container { max-width: 1100px; margin: 32px auto; padding: 0 24px; }
h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 1px;
     color: var(--accent); margin-bottom: 16px; }
.cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
        padding: 20px; }
.card .label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--muted); }
.card .value { font-size: 32px; font-weight: 700; color: var(--accent); margin-top: 6px; }
.card .sub   { font-size: 11px; color: var(--muted); margin-top: 4px; }
.panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
         padding: 24px; margin-bottom: 24px; }
/* Risk bars */
.risk-bar { margin-bottom: 14px; }
.risk-bar .row { display: flex; align-items: center; gap: 12px; margin-bottom: 4px; }
.risk-bar .lbl { width: 70px; font-size: 12px; font-weight: 600; }
.risk-bar .bar-wrap { flex: 1; background: var(--border); border-radius: 4px; height: 12px; }
.risk-bar .bar { height: 12px; border-radius: 4px; }
.risk-bar .cnt { width: 60px; font-size: 12px; color: var(--muted); text-align: right; }
.bar-critical { background: var(--critical); }
.bar-high     { background: var(--high); }
.bar-medium   { background: var(--medium); }
.bar-low      { background: var(--low); }
/* Table */
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; color: var(--muted); font-weight: 600; padding: 8px 10px;
     border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; }
td { padding: 8px 10px; border-bottom: 1px solid var(--border); }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; }
.badge-Critical { background: rgba(255,59,92,.15); color: var(--critical); }
.badge-High     { background: rgba(255,140,66,.15); color: var(--high); }
.badge-Medium   { background: rgba(255,209,102,.15); color: var(--medium); }
.badge-Low      { background: rgba(6,214,160,.15); color: var(--low); }
/* Pipeline steps */
.steps { display: flex; flex-direction: column; gap: 10px; }
.step { display: flex; align-items: center; gap: 12px; padding: 10px 14px;
        border-radius: 6px; border: 1px solid var(--border); }
.step.ok  { border-color: var(--low); }
.step.err { border-color: var(--critical); }
.step .icon { font-size: 16px; }
.step .name { font-weight: 600; flex: 1; }
.step .info { font-size: 12px; color: var(--muted); }
"""

# ---------------------------------------------------------------------------
# Artifact loading
# ---------------------------------------------------------------------------

def _load_json(path: Path) -> dict | list | None:
    if not path.exists():
        return None
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


# ---------------------------------------------------------------------------
# HTML generation helpers
# ---------------------------------------------------------------------------

def _stat_card(label: str, value: str | int | float, sub: str = "") -> str:
    sub_html = f'<div class="sub">{sub}</div>' if sub else ""
    return (
        f'<div class="card">'
        f'<div class="label">{label}</div>'
        f'<div class="value">{value}</div>'
        f'{sub_html}'
        f'</div>'
    )


def _risk_bar(label: str, count: int, total: int, css_class: str) -> str:
    pct = round(count / total * 100, 1) if total else 0
    width = f"{pct:.1f}%"
    return (
        f'<div class="risk-bar">'
        f'<div class="row">'
        f'<span class="lbl">{label}</span>'
        f'<div class="bar-wrap"><div class="bar {css_class}" style="width:{width}"></div></div>'
        f'<span class="cnt">{count}</span>'
        f'</div>'
        f'</div>'
    )


def _badge(level: str) -> str:
    return f'<span class="badge badge-{level}">{level}</span>'


def _pipeline_step(name: str, info: str, ok: bool = True) -> str:
    icon = "✅" if ok else "❌"
    css = "ok" if ok else "err"
    return (
        f'<div class="step {css}">'
        f'<span class="icon">{icon}</span>'
        f'<span class="name">{name}</span>'
        f'<span class="info">{info}</span>'
        f'</div>'
    )


# ---------------------------------------------------------------------------
# HTML report builder
# ---------------------------------------------------------------------------

def generate_html(
    alerts_data: list[dict],
    risk_summary: dict,
    experiments: list[dict],
    validation: dict,
) -> str:
    """Assemble the full HTML report as a string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Stat cards ──────────────────────────────────────────────────────────
    total_events = validation.get("total", 0) if validation else 0
    total_alerts = len(alerts_data)
    critical_count = risk_summary.get("Critical", 0) if risk_summary else 0
    auc = ""
    if experiments:
        last = experiments[-1]
        auc = f"{last.get('metrics', {}).get('auc_roc', 0):.4f}"
    else:
        auc = "N/A"

    cards_html = (
        _stat_card("Total Events", f"{total_events:,}", "validated")
        + _stat_card("Alerts", f"{total_alerts:,}", f"threshold ≥ 51")
        + _stat_card("Critical", str(critical_count), "risk level")
        + _stat_card("AUC-ROC", auc, "last run")
    )

    # ── Risk distribution bars ───────────────────────────────────────────────
    rs = risk_summary or {}
    total_rs = rs.get("total", 1) or 1
    bars_html = (
        _risk_bar("Critical", rs.get("Critical", 0), total_rs, "bar-critical")
        + _risk_bar("High",     rs.get("High",     0), total_rs, "bar-high")
        + _risk_bar("Medium",   rs.get("Medium",   0), total_rs, "bar-medium")
        + _risk_bar("Low",      rs.get("Low",      0), total_rs, "bar-low")
    )
    mean_s = rs.get("mean_score", 0)
    max_s  = rs.get("max_score",  0)
    dist_html = (
        f'<div class="panel">'
        f'<h2>Risk Distribution</h2>'
        f'{bars_html}'
        f'<p style="font-size:12px;color:var(--muted);margin-top:12px;">'
        f'Mean score: <strong>{mean_s:.2f}</strong> &nbsp;|&nbsp; '
        f'Max score: <strong>{max_s:.2f}</strong>'
        f'</p>'
        f'</div>'
    )

    # ── Top alerts table ─────────────────────────────────────────────────────
    top_alerts = sorted(alerts_data, key=lambda a: a.get("risk_score", 0), reverse=True)[:20]
    rows_html = ""
    for a in top_alerts:
        sev  = a.get("severity", "")
        atype = a.get("alert_type", "").replace("_", " ").title()
        score = a.get("risk_score", 0)
        aid  = a.get("alert_id", "")
        ts   = a.get("timestamp", "")[:19].replace("T", " ")
        rows_html += (
            f"<tr>"
            f"<td>{aid}</td>"
            f"<td>{_badge(sev)}</td>"
            f"<td>{atype}</td>"
            f"<td><strong>{score:.1f}</strong></td>"
            f"<td>{ts}</td>"
            f"</tr>"
        )
    alerts_html = (
        f'<div class="panel">'
        f'<h2>Top Alerts</h2>'
        f'<table>'
        f'<thead><tr><th>Alert ID</th><th>Severity</th><th>Type</th><th>Score</th><th>Time</th></tr></thead>'
        f'<tbody>{rows_html}</tbody>'
        f'</table>'
        f'</div>'
    )

    # ── Experiment history ───────────────────────────────────────────────────
    exp_rows = ""
    for e in reversed(experiments[-10:]):
        run_id  = e.get("run_id", "")
        metrics = e.get("metrics", {})
        auc_v   = metrics.get("auc_roc", 0)
        f1_v    = metrics.get("f1_score", 0)
        prec_v  = metrics.get("precision", 0)
        rec_v   = metrics.get("recall", 0)
        det_v   = metrics.get("detected_anomalies", 0)
        ts_e    = e.get("timestamp", "")[:19].replace("T", " ")
        exp_rows += (
            f"<tr>"
            f"<td>{run_id}</td>"
            f"<td>{ts_e}</td>"
            f"<td>{auc_v:.4f}</td>"
            f"<td>{f1_v:.4f}</td>"
            f"<td>{prec_v:.4f}</td>"
            f"<td>{rec_v:.4f}</td>"
            f"<td>{det_v}</td>"
            f"</tr>"
        )
    exp_html = (
        f'<div class="panel">'
        f'<h2>Experiment History (last 10)</h2>'
        f'<table>'
        f'<thead><tr>'
        f'<th>Run ID</th><th>Date</th><th>AUC-ROC</th>'
        f'<th>F1</th><th>Precision</th><th>Recall</th><th>Anomalies</th>'
        f'</tr></thead>'
        f'<tbody>{exp_rows if exp_rows else "<tr><td colspan=7>No runs recorded</td></tr>"}</tbody>'
        f'</table>'
        f'</div>'
    )

    # ── Pipeline status ──────────────────────────────────────────────────────
    v_ok  = bool(validation and validation.get("error_count", 1) == 0)
    steps_html = (
        _pipeline_step("Dataset Validation",    f"{total_events:,} events — {validation.get('error_count', '?')} errors",    v_ok)
        + _pipeline_step("Feature Engineering", f"11 features extracted",                                                    True)
        + _pipeline_step("IsolationForest",     f"AUC-ROC = {auc}",                                                         bool(experiments))
        + _pipeline_step("Risk Scoring",        f"Mean = {mean_s:.2f} / Max = {max_s:.2f}",                                 bool(risk_summary))
        + _pipeline_step("Alert Generation",    f"{total_alerts} alerts generated",                                          bool(alerts_data))
        + _pipeline_step("Experiment Tracking", f"{len(experiments)} run(s) recorded",                                       bool(experiments))
        + _pipeline_step("Dashboard",           "This report",                                                               True)
    )
    pipeline_html = (
        f'<div class="panel">'
        f'<h2>Pipeline Status</h2>'
        f'<div class="steps">{steps_html}</div>'
        f'</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CyberHealthGuard — Security Dashboard</title>
<style>{_CSS}</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; CyberHealthGuard</h1>
  <span>Security Intelligence Dashboard &nbsp;|&nbsp; Generated {now}</span>
</header>
<div class="container">
  <div class="cards">{cards_html}</div>
  {dist_html}
  {alerts_html}
  {exp_html}
  {pipeline_html}
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_report(
    artifacts_dir: Path,
    output_path: Optional[Path] = None,
) -> Path:
    """Read all pipeline artifacts and write the HTML dashboard.

    Parameters
    ----------
    artifacts_dir:
        Directory containing alerts.json, risk_summary.json,
        experiments.jsonl, validation_report.json.
    output_path:
        Destination HTML file. Defaults to ``artifacts_dir/dashboard.html``.

    Returns
    -------
    Path
        Absolute path to the generated HTML file.
    """
    artifacts_dir = Path(artifacts_dir).resolve()
    if output_path is None:
        output_path = artifacts_dir / "dashboard.html"
    output_path = Path(output_path).resolve()

    alerts_data = _load_json(artifacts_dir / "alerts.json") or []
    risk_summary = _load_json(artifacts_dir / "risk_summary.json") or {}
    validation   = _load_json(artifacts_dir / "validation_report.json") or {}
    experiments  = _load_jsonl(artifacts_dir / "experiments.jsonl")

    html = generate_html(alerts_data, risk_summary, experiments, validation)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Generate HTML security dashboard")
    parser.add_argument(
        "--artifacts", default="artifacts",
        help="Directory with pipeline artifacts (default: artifacts/)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Output HTML path (default: <artifacts>/dashboard.html)",
    )
    args = parser.parse_args()

    out = generate_report(
        Path(args.artifacts),
        Path(args.output) if args.output else None,
    )
    print(f"Dashboard written → {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
