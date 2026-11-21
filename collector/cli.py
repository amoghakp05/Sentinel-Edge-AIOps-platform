"""
collector/cli.py
─────────────────
Typer-based collector CLI for Sentinel Edge.

Commands:
  collector run                      - Start collector daemon
  collector status                   - Current daemon & queue status
  collector raw tail                 - Show recent un-redacted raw records (local only)
  collector egress tail              - Live table of every payload: time, payload_id, status, SHA-256, destination
  collector egress show <id>         - Side-by-side display: RAW (secrets) vs EGRESS JSON (metadata only)
  collector buffer                   - Outbox depth, oldest pending age, connection state (Online / Buffering)
  collector policy test <file>       - Validate candidate payload against allow-list policy
  collector verify-hash <id>         - Cryptographically recompute and compare SHA-256 hash
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from pathlib import Path
from typing import Optional

# Ensure UTF-8 console encoding on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from collector import egress_log, outbox, policy
from collector.db import get_db

app = typer.Typer(
    name="collector",
    help="Sentinel Edge local collector CLI.",
    no_args_is_help=True,
)
raw_app = typer.Typer(help="Commands for inspecting local raw telemetry.")
egress_app = typer.Typer(help="Commands for inspecting allow-listed egress payloads.")
policy_app = typer.Typer(help="Commands for testing allow-list compliance.")

app.add_typer(raw_app, name="raw")
app.add_typer(egress_app, name="egress")
app.add_typer(policy_app, name="policy")

console = Console(stderr=True)
out = Console()


# ── collector run ─────────────────────────────────────────────────────────────

@app.command("run")
def run(
    adapter: str = typer.Option("sim", "--adapter", "-a", help="Input adapter: sim | psutil | syslog"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Start collector processing pipeline."""
    if as_json:
        out.print(json.dumps({"status": "running", "adapter": adapter}))
    else:
        console.print(f"[bold green]Starting Sentinel Edge Collector...[/bold green] (adapter: {adapter})")


# ── collector status ──────────────────────────────────────────────────────────

@app.command("status")
def status(as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format")) -> None:
    """Display status of the collector daemon and local storage."""
    conn = get_db()
    raw_count = conn.execute("SELECT count(*) FROM raw_events").fetchone()[0]
    out_stats = outbox.get_outbox_stats()
    egress_count = conn.execute("SELECT count(*) FROM egress_log").fetchone()[0]

    stat = {
        "collector_id": os.environ.get("COLLECTOR_ID", "col-acme-eu-1"),
        "raw_events_count": raw_count,
        "outbox_buffer_depth": out_stats["pending_count"],
        "connection_state": out_stats["state"],
        "egress_logged_count": egress_count,
        "journal_mode": conn.execute("PRAGMA journal_mode;").fetchone()[0],
    }
    if as_json:
        out.print(json.dumps(stat))
    else:
        table = Table(title="Collector Node Status")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        for k, v in stat.items():
            table.add_row(k, str(v))
        out.print(table)


# ── collector buffer ──────────────────────────────────────────────────────────

@app.command("buffer")
def buffer(as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format")) -> None:
    """
    Shows outbox queue depth, oldest pending age, and connection state (Online / Buffering).
    """
    stats = outbox.get_outbox_stats()

    if as_json:
        out.print(json.dumps(stats))
        return

    table = Table(title="Outbox Store-and-Forward Buffer")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")

    state_color = "green" if stats["state"] == "Online" else "yellow"
    table.add_row("Connection State", f"[{state_color}]{stats['state']}[/{state_color}]")
    table.add_row("Queue Depth", str(stats["pending_count"]))
    table.add_row("Oldest Pending Age", f"{stats['oldest_age_s']} seconds")
    table.add_row("Oldest Pending Created At", str(stats["oldest_created_at"] or "N/A"))

    out.print(table)


# ── collector raw tail ────────────────────────────────────────────────────────

@raw_app.command("tail")
def raw_tail(
    n: int = typer.Option(20, "--n", "-n", help="Number of recent events to show."),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="Output as JSON lines (one per event)."),
    adapter: Optional[str] = typer.Option(None, "--adapter", "-a", help="Filter by adapter name: psutil | sim | syslog"),
) -> None:
    """Print the latest raw events from the local database."""
    conn = get_db()
    query = "SELECT id, received_at, source, source_tz, category, value, unit, raw_text, adapter FROM raw_events"
    params = []
    if adapter:
        query += " WHERE adapter = ?"
        params.append(adapter)
    query += " ORDER BY received_at DESC LIMIT ?"
    params.append(n)

    rows = conn.execute(query, params).fetchall()

    if not rows:
        if as_json:
            out.print("[]")
        else:
            console.print("[yellow]No raw events in local database.[/yellow]")
        return

    if as_json:
        for row in rows:
            out.print(json.dumps(dict(row)))
        return

    table = Table(
        title=f"[bold red]LOCAL ONLY — Raw Events (n={n})[/bold red]\n"
              "[dim]These rows contain real hostnames, IPs, and secrets — they NEVER leave this machine.[/dim]",
        show_lines=True,
        expand=True,
    )
    table.add_column("ID", style="dim", width=6)
    table.add_column("Received (UTC)", style="cyan", width=22)
    table.add_column("Adapter", style="magenta", width=8)
    table.add_column("Category", style="green", width=12)
    table.add_column("Value", style="yellow", width=10)
    table.add_column("Source ⚠", style="bold red", width=20)
    table.add_column("Raw Text ⚠ (secrets visible)", width=50)

    for row in rows:
        value_str = f"{row['value']:.2f} {row['unit'] or ''}" if row["value"] is not None else "—"
        raw_snippet = (row["raw_text"] or "")[:200]
        secret_markers = ["password=", "token=", "secret=", "api_key="]
        has_secret = any(m in raw_snippet.lower() for m in secret_markers)
        raw_cell = Text(raw_snippet)
        if has_secret:
            raw_cell.stylize("bold red")

        table.add_row(
            str(row["id"]),
            str(row["received_at"]),
            str(row["adapter"]),
            str(row["category"]),
            value_str,
            str(row["source"]),
            raw_cell,
        )

    out.print(table)


# ── collector egress tail ─────────────────────────────────────────────────────

@egress_app.command("tail")
def egress_tail(
    n: int = typer.Option(20, "--n", "-n", help="Number of egress events to tail"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """
    Live table of every payload: time, payload_id, status, SHA-256, destination.
    """
    rows = egress_log.tail_egress(limit=n)

    if as_json:
        out.print(json.dumps(rows))
        return

    table = Table(title=f"Egress Log: Proof of Transmission (Latest {len(rows)})")
    table.add_column("Seq", style="dim", width=6)
    table.add_column("Time (UTC)", style="cyan", width=22)
    table.add_column("Payload ID", style="magenta", width=36)
    table.add_column("Status", style="bold", width=10)
    table.add_column("SHA-256", style="yellow", width=18)
    table.add_column("Destination", style="blue")

    for r in rows:
        stat_color = "green" if r["status"] == "acked" else "yellow"
        sha_display = f"{r['sha256'][:16]}..."
        table.add_row(
            str(r["seq"]),
            r["ts_utc"],
            r["payload_id"],
            f"[{stat_color}]{r['status']}[/{stat_color}]",
            sha_display,
            r["destination"],
        )

    if not rows:
        console.print("[dim]No egress logs found.[/dim]")
    else:
        out.print(table)


# ── collector egress show <id> ────────────────────────────────────────────────

@egress_app.command("show")
def egress_show(
    payload_id: str = typer.Argument(..., help="Payload ID to inspect"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="Output as raw JSON"),
) -> None:
    """
    Side-by-side inspection:
      LEFT  = Raw source lines with secrets (from local raw_events)
      RIGHT = Exact JSON metadata transmitted (allow-listed)
    Includes cryptographic hash verification against SaaS ACK hash.
    """
    record = egress_log.get_egress_record(payload_id)
    if not record:
        console.print(f"[red]Payload '{payload_id}' not found in egress log.[/red]")
        raise typer.Exit(code=1)

    # Find raw source line(s) around the same time
    conn = get_db()
    raw_row = conn.execute(
        """
        SELECT raw_text, source, received_at FROM raw_events
        ORDER BY abs(julianday(received_at) - julianday(?)) ASC
        LIMIT 1
        """,
        (record["ts_utc"],),
    ).fetchone()

    raw_text_display = raw_row["raw_text"] if raw_row else "(Raw source record cleared by retention or generated synthetically)"

    # Format JSON payload nicely
    try:
        parsed_payload = json.loads(record["exact_json"])
        formatted_json = json.dumps(parsed_payload, indent=2)
    except Exception:
        formatted_json = record["exact_json"]

    if as_json:
        res = {
            "payload_id": payload_id,
            "raw_source_line": raw_text_display,
            "exact_json_egressed": parsed_payload,
            "sha256": record["sha256"],
            "saas_ack_hash": record["saas_ack_hash"],
            "hash_matches": bool(record["saas_ack_hash"] and hmac.compare_digest(record["sha256"], record["saas_ack_hash"])),
        }
        out.print(json.dumps(res, indent=2))
        return

    # Side-by-side Rich Table
    grid = Table(title=f"Egress Audit: {payload_id}", expand=True, show_lines=True)
    grid.add_column("[bold red]LEFT: RAW SOURCE (LOCAL ONLY — SECRETS VISIBLE)[/bold red]", style="red")
    grid.add_column("[bold green]RIGHT: EGRESS PAYLOAD (METADATA ONLY — ALLOW-LISTED)[/bold green]", style="green")

    grid.add_row(raw_text_display, formatted_json)
    out.print(grid)

    # Verification banner
    sha = record["sha256"]
    ack_hash = record["saas_ack_hash"]
    if ack_hash and hmac.compare_digest(ack_hash, sha):
        out.print(f"[bold green]✓ hash matches SaaS (verified cryptographic ACK: {sha})[/bold green]")
    elif ack_hash:
        out.print(f"[bold yellow]! SaaS ack hash mismatch (local: {sha[:16]}..., saas: {ack_hash[:16]}...)[/bold yellow]")
    else:
        out.print(f"[dim]SHA-256: {sha} (Awaiting SaaS acknowledgement)[/dim]")


# ── collector verify-hash <id> ────────────────────────────────────────────────

@app.command("verify-hash")
def verify_hash(
    payload_id: str = typer.Argument(..., help="Payload ID to verify"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Verify cryptographic SHA-256 checksum of an egress payload against its recorded hash."""
    record = egress_log.get_egress_record(payload_id)
    if not record:
        console.print(f"[red]Payload '{payload_id}' not found.[/red]")
        raise typer.Exit(code=1)

    calc_sha = hashlib.sha256(record["exact_json"].encode("utf-8")).hexdigest()
    matched = bool(record["sha256"] and hmac.compare_digest(calc_sha, record["sha256"]))

    res = {
        "payload_id": payload_id,
        "recorded_sha256": record["sha256"],
        "calculated_sha256": calc_sha,
        "verified": matched,
    }

    if as_json:
        out.print(json.dumps(res))
    else:
        if matched:
            console.print(f"[bold green]✓ Cryptographic match: SHA-256 matches recorded hash ({calc_sha[:16]}...)[/bold green]")
        else:
            console.print("[bold red]✗ Hash mismatch! Potential payload tampering detected.[/bold red]")


# ── collector policy test <file> ──────────────────────────────────────────────

@policy_app.command("test")
def policy_test(
    file_path: Path = typer.Argument(..., help="Path to sample payload file (.json)"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Validate a candidate JSON payload against the egress allow-list policy."""
    if not file_path.exists():
        console.print(f"[red]File {file_path} does not exist.[/red]")
        raise typer.Exit(code=1)

    try:
        content = json.loads(file_path.read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Invalid JSON: {type(exc).__name__}[/red]")
        raise typer.Exit(code=1)

    allowed, filtered, reason = policy.enforce_policy(content)

    res = {
        "file": str(file_path),
        "allow_list_compliant": allowed,
        "reason": reason,
    }

    if as_json:
        out.print(json.dumps(res))
    else:
        if allowed:
            console.print("[bold green]✓ Payload passes allow-list policy.[/bold green]")
        else:
            console.print(f"[bold red]✗ Policy violation detected! Reason: {reason}[/bold red]")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
