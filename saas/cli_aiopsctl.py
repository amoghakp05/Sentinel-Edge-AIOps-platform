"""
saas/cli_aiopsctl.py
────────────────────
SaaS-side operator CLI for Sentinel Edge AIOps.

Commands:
  aiopsctl health              - Query fleet and tenant health states
  aiopsctl collectors          - List registered collectors and live heartbeat status
  aiopsctl incidents           - List correlated incidents and open alerts
  aiopsctl why <incident_id>   - Deep-dive into root cause, reasoning chain & confidence
  aiopsctl inject <scenario>   - Inject simulated scenario via SaaS proxy
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import typer
from rich.console import Console
from rich.table import Table

from saas.db import get_connection, init_db
from saas.health import evaluate_tenant_health
from saas.tenancy import get_scoped_query

app = typer.Typer(
    name="aiopsctl",
    help="Central SaaS AIOps Operator CLI.",
    no_args_is_help=True,
)

console = Console(stderr=True)
out = Console()


@app.command("health")
def health(
    tenant: Optional[str] = typer.Option("acme", "--tenant", "-t", help="Tenant ID"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Show current health state across tenants, collectors, and monitored entities."""
    init_db()
    tenant_id = tenant or "acme"
    try:
        evaluate_tenant_health(tenant_id)
    except Exception:
        pass

    states = get_scoped_query(
        tenant_id,
        table="health_state",
        order_by="updated_utc DESC",
    )

    if as_json:
        out.print(json.dumps(states, indent=2))
        return

    table = Table(title=f"Entity Health Status (Tenant: {tenant_id})")
    table.add_column("Tenant", style="cyan")
    table.add_column("Entity ID", style="magenta")
    table.add_column("Health State", style="bold")
    table.add_column("Reason", style="yellow")
    table.add_column("Updated (UTC)", style="dim")

    for s in states:
        state_str = s.get("state", "Unknown")
        color = (
            "green"
            if state_str == "Excellent"
            else ("blue" if state_str == "Good" else ("yellow" if state_str == "Fair" else "red"))
        )
        table.add_row(
            s.get("tenant_id", tenant_id),
            s.get("entity_id", "unknown"),
            f"[{color}]{state_str}[/{color}]",
            s.get("reason", ""),
            s.get("updated_utc", ""),
        )
    out.print(table)


@app.command("collectors")
def collectors(
    tenant: Optional[str] = typer.Option("acme", "--tenant", "-t", help="Tenant ID"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Show all collectors registered to the tenant with live status and metrics."""
    init_db()
    tenant_id = tenant or "acme"
    rows = get_scoped_query(tenant_id, table="collectors")

    now_utc = datetime.now(timezone.utc)
    results: List[Dict[str, Any]] = []

    for r in rows:
        last_seen = r.get("last_seen")
        is_offline = True
        seconds_ago = None
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                diff = (now_utc - dt).total_seconds()
                seconds_ago = round(diff, 1)
                is_offline = diff >= 60.0
            except Exception:
                is_offline = True

        status = "offline" if is_offline else r.get("status", "active")
        results.append({
            "id": r.get("id"),
            "tenant_id": tenant_id,
            "status": status,
            "is_offline": is_offline,
            "last_seen": last_seen,
            "seconds_since_heartbeat": seconds_ago,
            "version": r.get("version") or "unknown",
            "cpu": r.get("cpu"),
            "mem": r.get("mem"),
            "queue_depth": r.get("queue_depth", 0),
            "config_hash": r.get("config_hash") or "unknown",
        })

    if as_json:
        out.print(json.dumps(results, indent=2))
        return

    table = Table(title=f"Registered Collectors (Tenant: {tenant_id})")
    table.add_column("Collector ID", style="cyan")
    table.add_column("Status", style="bold")
    table.add_column("Last Seen", style="dim")
    table.add_column("Version", style="magenta")
    table.add_column("CPU %", justify="right")
    table.add_column("Mem %", justify="right")
    table.add_column("Queue Depth", justify="right")
    table.add_column("Config Hash", style="dim")

    for c in results:
        stat_color = "red" if c["is_offline"] else "green"
        stat_label = f"[{stat_color}]{c['status'].upper()}[/{stat_color}]"
        cpu_val = f"{c['cpu']:.1f}%" if c.get("cpu") is not None else "-"
        mem_val = f"{c['mem']:.1f}%" if c.get("mem") is not None else "-"
        table.add_row(
            c["id"],
            stat_label,
            c["last_seen"] or "never",
            c["version"],
            cpu_val,
            mem_val,
            str(c.get("queue_depth") if c.get("queue_depth") is not None else 0),
            c["config_hash"][:12] if c.get("config_hash") else "-",
        )
    out.print(table)


@app.command("incidents")
def incidents(
    tenant: Optional[str] = typer.Option("acme", "--tenant", "-t", help="Tenant ID"),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status: open | closed"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """List correlated incidents generated by the AIOps engine."""
    init_db()
    tenant_id = tenant or "acme"

    where_clause = "status = ?" if status else None
    params = [status] if status else None

    rows = get_scoped_query(
        tenant_id,
        table="incidents",
        where_clause=where_clause,
        params=params,
        order_by="updated_utc DESC",
    )

    incidents_list: List[Dict[str, Any]] = []
    for r in rows:
        item = dict(r)
        try:
            item["affected_components"] = json.loads(item.get("affected_json") or "[]")
        except Exception:
            item["affected_components"] = []
        incidents_list.append(item)

    if as_json:
        out.print(json.dumps(incidents_list, indent=2))
        return

    table = Table(title=f"Correlated AIOps Incidents (Tenant: {tenant_id})")
    table.add_column("Incident ID", style="cyan")
    table.add_column("Severity", style="bold red")
    table.add_column("Title", style="yellow")
    table.add_column("Root Cause Candidate", style="magenta")
    table.add_column("Suppressed Alerts", justify="right", style="green")
    table.add_column("Status", style="bold")
    table.add_column("Opened UTC", style="dim")

    for i in incidents_list:
        sev = i.get("severity", "info").upper()
        sev_color = "red" if sev == "CRITICAL" else ("yellow" if sev == "WARNING" else "blue")
        table.add_row(
            i.get("id"),
            f"[{sev_color}]{sev}[/{sev_color}]",
            i.get("title", ""),
            i.get("root_cause_candidate", ""),
            str(i.get("suppressed_count", 0)),
            i.get("status", "open"),
            i.get("opened_utc", ""),
        )
    out.print(table)


@app.command("why")
def why(
    incident_id: str = typer.Argument(..., help="Incident ID to inspect (e.g. inc-019349...)"),
    tenant: Optional[str] = typer.Option("acme", "--tenant", "-t", help="Tenant ID"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Explain root-cause reasoning, signal weights, and confidence for an incident."""
    init_db()
    tenant_id = tenant or "acme"

    rows = get_scoped_query(
        tenant_id,
        table="incidents",
        where_clause="id = ?",
        params=[incident_id],
    )
    if not rows:
        console.print(f"[bold red]Error:[/bold red] Incident '{incident_id}' not found for tenant '{tenant_id}'")
        raise typer.Exit(code=1)

    inc = dict(rows[0])
    try:
        inc["affected_components"] = json.loads(inc.get("affected_json") or "[]")
    except Exception:
        inc["affected_components"] = []

    # Query recommendations via tenant-scoped function
    recs: List[Dict[str, Any]] = []
    rec_rows = get_scoped_query(
        tenant_id,
        table="recommendations",
        where_clause="incident_id = ?",
        params=[incident_id],
    )
    for r in rec_rows:
        recs.append({
            "pattern": r["pattern"],
            "likely_cause": r["likely_cause"],
            "action": r["action"],
            "signals": json.loads(r["signals_json"]) if r["signals_json"] else [],
            "confidence": r["confidence"],
            "reasoning_path": json.loads(r["reasoning_json"]) if r["reasoning_json"] else [],
        })

    # Aggregate signals and reasoning across recommendations
    primary_rec = recs[0] if recs else {}
    signals = primary_rec.get("signals", [])
    reasoning_path = primary_rec.get("reasoning_path", [])
    confidence = primary_rec.get("confidence", 0.85)

    suppressed = inc.get("suppressed_count", 0)
    alerts_summary = f"{suppressed + 1} alerts reduced to 1 incident"

    explanation = {
        "incident_id": incident_id,
        "tenant_id": tenant_id,
        "title": inc.get("title", ""),
        "severity": inc.get("severity", ""),
        "root_cause_candidate": inc.get("root_cause_candidate", ""),
        "suppressed_count": suppressed,
        "alerts_summary": alerts_summary,
        "confidence": confidence,
        "signals": signals,
        "reasoning_path": reasoning_path,
        "recommendations": recs,
    }

    if as_json:
        out.print(json.dumps(explanation, indent=2))
        return

    out.print(f"\n[bold cyan]═══ Root Cause Analysis: {incident_id} ═══[/bold cyan]")
    out.print(f"[bold]Title:[/bold] {inc.get('title')}")
    out.print(f"[bold]Root Cause Candidate:[/bold] [bold magenta]{inc.get('root_cause_candidate')}[/bold magenta]")
    out.print(f"[bold]Correlated Impact:[/bold] [bold green]{alerts_summary}[/bold green]")
    out.print(f"[bold]Confidence:[/bold] [bold green]{confidence * 100:.0f}%[/bold green]\n")

    out.print("[bold yellow]Contributing Signals & Standardized Deviations:[/bold yellow]")
    if signals:
        for s in signals:
            sig_name = s if isinstance(s, str) else s.get("signal", str(s))
            wt = s.get("weight") if isinstance(s, dict) and "weight" in s else None
            wt_str = f" (weight: {wt:.2f})" if wt is not None else ""
            out.print(f"  • [bold]{sig_name}[/bold]{wt_str}")
    else:
        out.print("  • Primary alert signal")

    out.print("\n[bold yellow]Reasoning Path & Topological Linkages:[/bold yellow]")
    if reasoning_path:
        for idx, step in enumerate(reasoning_path, 1):
            out.print(f"  {idx}. {step}")
    else:
        out.print("  1. Alert grouped within sliding correlation window")

    out.print("\n[bold yellow]Automated Recommendations:[/bold yellow]")
    if recs:
        for r in recs:
            out.print(f"  • [bold]{r.get('likely_cause', '')}:[/bold] {r.get('action', '')}")
    else:
        out.print("  • Manual inspection recommended.")
    out.print("")


@app.command("inject")
def inject(
    scenario: Optional[str] = typer.Argument(
        None,
        help="Scenario number (1-8), name (secret, outage, latency, etc.), 0 for reset, 9 for rehearsal",
    ),
    collector: str = typer.Option("col-acme-eu-1", "--collector", "-c", help="Target collector ID"),
    tenant: str = typer.Option("acme", "--tenant", "-t", help="Tenant ID"),
    menu: bool = typer.Option(False, "--menu", "-m", help="Open interactive menu"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Trigger a scenario via simulator proxy, run rehearsal, or open interactive menu."""
    from tools.scenario_injector import interactive_menu, run_scenario

    if menu or scenario is None:
        interactive_menu(collector_id=collector, tenant_id=tenant)
    else:
        run_scenario(
            scenario_input=scenario,
            collector_id=collector,
            tenant_id=tenant,
            as_json=as_json,
        )


@app.command("reset")
def reset(
    collector: str = typer.Option("all", "--collector", "-c", help="Target collector ID or 'all'"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Reset all chaos injections and return platform to normal diurnal baseline."""
    from tools.scenario_injector import reset_baseline

    reset_baseline(collector_id=collector, as_json=as_json)


@app.command("rehearsal")
def rehearsal(
    collector: str = typer.Option("col-acme-eu-1", "--collector", "-c", help="Target collector ID"),
    tenant: str = typer.Option("acme", "--tenant", "-t", help="Tenant ID"),
    delay: float = typer.Option(2.5, "--delay", "-d", help="Seconds between scenarios"),
    as_json: bool = typer.Option(False, "--json", is_flag=True, help="JSON output format"),
) -> None:
    """Run all 8 judging scenarios in order for demo rehearsal, followed by baseline reset."""
    from tools.scenario_injector import run_all_scenarios

    run_all_scenarios(collector_id=collector, tenant_id=tenant, delay_s=delay, as_json=as_json)


def main() -> None:
    app()


if __name__ == "__main__":
    main()
