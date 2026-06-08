"""
utils/ransomware_escalation.py
───────────────────────────────
Traffic Light / Rule-Based Escalation engine — Malaysia ransomware incidents only.

Applies a plain if-then rule engine to each victim row from the
`ransomware_victims` (Malaysia) table and assigns one of four escalation levels:

    🔴  ESCALATE NOW   — immediate analyst action required
    🟠  RESPOND TODAY  — respond within the working day
    🟡  MONITOR        — track but no immediate action needed
    🟢  LOG & CLOSE    — low priority, archive only

Usage (from application.py inside page_ransomware, Malaysia tab):
──────────────────────────────────────────────────────────────────
    from utils.ransomware_escalation import render_escalation_panel
    # inside the `with tab_malaysia:` block, after _render_ransomware_section:
    render_escalation_panel(my_raw)
"""

from __future__ import annotations

import pandas as pd
import streamlit as st
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

TZ_MY = ZoneInfo("Asia/Kuala_Lumpur")
def _now() -> datetime:
    return datetime.now(tz=TZ_MY)


# ══════════════════════════════════════════════════════════════════════════════
#  ESCALATION LEVELS
# ══════════════════════════════════════════════════════════════════════════════

LEVELS = {
    "ESCALATE NOW":  {"emoji": "🔴", "color": "#ff6b6b", "bg": "#3d0f0f", "border": "#ff6b6b", "order": 0},
    "RESPOND TODAY": {"emoji": "🟠", "color": "#ffa94d", "bg": "#2d1b0a", "border": "#ffa94d", "order": 1},
    "MONITOR":       {"emoji": "🟡", "color": "#f5c518", "bg": "#2a2200", "border": "#f5c518", "order": 2},
    "LOG & CLOSE":   {"emoji": "🟢", "color": "#3fb950", "bg": "#0a1f17", "border": "#3fb950", "order": 3},
}

# Critical sectors for Malaysia — escalation is higher when these are hit
CRITICAL_SECTORS = {
    "government", "defence", "defense", "healthcare", "health",
    "finance", "banking", "financial services", "energy", "utilities",
    "telecommunications", "telco", "critical infrastructure",
    "water", "transportation", "education",
}

# Known high-risk / prolific threat actors operating in Southeast Asia
HIGH_RISK_ACTORS = {
    "lockbit", "lockbit 3.0", "lockbit3", "alphv", "blackcat",
    "cl0p", "clop", "black basta", "blackbasta", "play", "royal",
    "8base", "rhysida", "akira", "hunters international", "medusa",
    "ransomhub", "ransomhouse", "darkvault", "cactus", "incransom",
}


# ══════════════════════════════════════════════════════════════════════════════
#  RULE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _apply_rules(row: pd.Series, hours_threshold: int) -> tuple[str, list[str]]:
    """
    Evaluate all rules for a single victim row.

    Returns
    -------
    level   : one of the LEVELS keys
    triggers: list of human-readable rule descriptions that fired
    """
    triggered: list[str] = []

    # ── Extract & normalise fields ────────────────────────────────────────────
    sector      = str(row.get("sector",       "")).strip().lower()
    severity    = str(row.get("severity",     "")).strip().lower()
    threat_actor= str(row.get("threat_actor", "")).strip().lower()
    date_val    = row.get("date", pd.NaT)

    is_critical_sector  = any(s in sector      for s in CRITICAL_SECTORS)
    is_high_risk_actor  = any(a in threat_actor for a in HIGH_RISK_ACTORS)
    is_critical_sev     = severity in ("critical",)
    is_high_sev         = severity in ("high",)
    is_recent           = False

    if pd.notna(date_val):
        try:
            dt = pd.to_datetime(date_val, utc=True).tz_convert(TZ_MY)
            is_recent = ((_now() - dt).total_seconds() / 3600) <= hours_threshold
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    #  RULE DEFINITIONS
    #  Rules are evaluated top-down; the FIRST matching level wins.
    #  Each rule appends a trigger description regardless so analysts can see
    #  all conditions that were met (not just the deciding one).
    # ─────────────────────────────────────────────────────────────────────────

    # R1 — Critical severity + critical sector → immediate escalation
    if is_critical_sev and is_critical_sector:
        triggered.append(f"R1 · Critical severity on a critical sector ({sector})")

    # R2 — Critical severity + known high-risk actor
    if is_critical_sev and is_high_risk_actor:
        triggered.append(f"R2 · Critical severity by high-risk actor ({threat_actor})")

    # R3 — Critical sector hit within recency window
    if is_critical_sector and is_recent:
        triggered.append(f"R3 · Critical sector ({sector}) attacked within {hours_threshold}h")

    # R4 — High-risk actor + critical sector
    if is_high_risk_actor and is_critical_sector:
        triggered.append(f"R4 · High-risk actor ({threat_actor}) targeting critical sector ({sector})")

    # R5 — Any critical severity
    if is_critical_sev:
        triggered.append("R5 · Severity is Critical")

    # R6 — High severity + recent
    if is_high_sev and is_recent:
        triggered.append(f"R6 · High severity within {hours_threshold}h")

    # R7 — High-risk actor + recent
    if is_high_risk_actor and is_recent:
        triggered.append(f"R7 · High-risk actor ({threat_actor}) within {hours_threshold}h")

    # R8 — High severity + critical sector
    if is_high_sev and is_critical_sector:
        triggered.append(f"R8 · High severity on critical sector ({sector})")

    # R9 — High severity alone
    if is_high_sev:
        triggered.append("R9 · Severity is High")

    # R10 — High-risk actor alone
    if is_high_risk_actor:
        triggered.append(f"R10 · Known high-risk actor ({threat_actor})")

    # R11 — Critical sector alone (no other signal)
    if is_critical_sector:
        triggered.append(f"R11 · Critical sector targeted ({sector})")

    # R12 — Recent incident (no other signal)
    if is_recent:
        triggered.append(f"R12 · Incident within {hours_threshold}h")

    # ── Decision: highest-priority rule group wins ────────────────────────────
    escalate_rules  = {"R1", "R2", "R3", "R4"}
    respond_rules   = {"R5", "R6", "R7", "R8"}
    monitor_rules   = {"R9", "R10", "R11", "R12"}

    fired_ids = {t.split("·")[0].strip() for t in triggered}

    if fired_ids & escalate_rules:
        level = "ESCALATE NOW"
    elif fired_ids & respond_rules:
        level = "RESPOND TODAY"
    elif fired_ids & monitor_rules:
        level = "MONITOR"
    else:
        level = "LOG & CLOSE"

    return level, triggered


def apply_escalation(df: pd.DataFrame, hours_threshold: int = 48) -> pd.DataFrame:
    """
    Apply the rule engine to every row and return the DataFrame with two new columns:
        escalation_level   — one of the LEVELS keys
        escalation_triggers — pipe-separated list of fired rule descriptions
    """
    if df is None or df.empty:
        return df

    results = df.apply(lambda row: _apply_rules(row, hours_threshold), axis=1)
    df = df.copy()
    df["escalation_level"]    = results.apply(lambda x: x[0])
    df["escalation_triggers"] = results.apply(lambda x: " | ".join(x[1]) if x[1] else "No rules fired")
    return df


# ══════════════════════════════════════════════════════════════════════════════
#  UI — FULL ESCALATION PANEL
# ══════════════════════════════════════════════════════════════════════════════

def render_escalation_panel(df_raw: pd.DataFrame) -> None:
    """
    Render the full Traffic Light Escalation panel for Malaysia ransomware data.

    Call this from inside the `with tab_malaysia:` block in page_ransomware().
    """

    if df_raw is None or df_raw.empty:
        st.warning("⚠️ No Malaysia ransomware data available for escalation analysis.")
        return

    # ── Prepare data ──────────────────────────────────────────────────────────
    df = df_raw.copy()
    if "date" in df.columns:
        df["date"] = pd.to_datetime(df["date"], errors="coerce", utc=True).dt.tz_convert(TZ_MY)

    # ── Sidebar controls ──────────────────────────────────────────────────────
    with st.sidebar:
        st.markdown(
            "<div style='font-size:10px;font-weight:600;color:#484f58;"
            "text-transform:uppercase;letter-spacing:.12em;"
            "padding:12px 16px 4px;margin-top:10px;'>🚦 Escalation Settings</div>",
            unsafe_allow_html=True,
        )
        hours_threshold = st.slider(
            "Recency window (hours)",
            min_value=6, max_value=168, value=48, step=6,
            key="esc_hours",
            help="Incidents within this window are treated as 'recent' — increases escalation level.",
        )
        show_rules = st.toggle(
            "Show triggered rules on cards",
            value=True,
            key="esc_show_rules",
        )
        filter_level = st.multiselect(
            "Filter by escalation level",
            options=list(LEVELS.keys()),
            default=list(LEVELS.keys()),
            key="esc_filter_level",
        )

    # ── Run engine ────────────────────────────────────────────────────────────
    with st.spinner("Applying escalation rules…"):
        scored = apply_escalation(df, hours_threshold=hours_threshold)

    # ── Apply level filter ────────────────────────────────────────────────────
    filtered = scored[scored["escalation_level"].isin(filter_level)].copy()

    # Sort by escalation priority then date descending
    level_order = {k: v["order"] for k, v in LEVELS.items()}
    filtered["_sort_order"] = filtered["escalation_level"].map(level_order)
    date_col = "date" if "date" in filtered.columns else None
    sort_cols = ["_sort_order"] + ([date_col] if date_col else [])
    sort_asc  = [True] + ([False] if date_col else [])
    filtered  = filtered.sort_values(sort_cols, ascending=sort_asc).reset_index(drop=True)

    # ── Section header ────────────────────────────────────────────────────────
    st.markdown(
        "<div class='section-header'>🚦 Incidents Escalation · Malaysia Ransomware</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "<div style='font-size:13px;color:#8b949e;margin-bottom:16px;'>"
        "Each Malaysia victim is evaluated against a plain if-then rule engine. "
        "Rules consider <b style='color:#c9d1d9;'>severity</b>, "
        "<b style='color:#c9d1d9;'>sector criticality</b>, "
        "<b style='color:#c9d1d9;'>threat actor risk</b>, and "
        "<b style='color:#c9d1d9;'>recency</b></div>",
        unsafe_allow_html=True,
    )

    # ── KPI summary row ───────────────────────────────────────────────────────
    counts = scored["escalation_level"].value_counts()
    k_cols = st.columns(4)
    for col, (lvl, meta) in zip(k_cols, LEVELS.items()):
        n = counts.get(lvl, 0)
        col.markdown(
            f"<div class='kpi-card' style='border-left:3px solid {meta['color']};'>"
            f"<div class='kpi-number' style='color:{meta['color']};font-size:32px;'>{n}</div>"
            f"<div class='kpi-label'>{meta['emoji']} {lvl}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Rule legend (collapsible) ─────────────────────────────────────────────
    with st.expander("📋 Rule Definitions — click to read the full rulebook"):
        st.markdown(f"""
| Rule | Condition | Level |
|------|-----------|-------|
| R1 | Critical severity **+** critical sector | 🔴 ESCALATE NOW |
| R2 | Critical severity **+** high-risk threat actor | 🔴 ESCALATE NOW |
| R3 | Critical sector attacked within **{hours_threshold}h** | 🔴 ESCALATE NOW |
| R4 | High-risk threat actor targeting critical sector | 🔴 ESCALATE NOW |
| R5 | Severity = Critical (any other conditions) | 🟠 RESPOND TODAY |
| R6 | High severity **+** within **{hours_threshold}h** | 🟠 RESPOND TODAY |
| R7 | High-risk threat actor **+** within **{hours_threshold}h** | 🟠 RESPOND TODAY |
| R8 | High severity **+** critical sector | 🟠 RESPOND TODAY |
| R9 | Severity = High (alone) | 🟡 MONITOR |
| R10 | Known high-risk threat actor (alone) | 🟡 MONITOR |
| R11 | Critical sector targeted (alone) | 🟡 MONITOR |
| R12 | Incident within **{hours_threshold}h** (alone) | 🟡 MONITOR |
| — | None of the above fired | 🟢 LOG & CLOSE |

**Critical sectors:** Government · Defence · Healthcare · Finance · Banking · Energy · Utilities · Telco · Critical Infrastructure · Water · Transportation · Education

**High-risk actors:** LockBit · ALPHV/BlackCat · Cl0p · Black Basta · Play · Royal · 8Base · Rhysida · Akira · Hunters International · Medusa · RansomHub · Cactus · INC Ransom · DarkVault
        """)

    # ── Victim cards ──────────────────────────────────────────────────────────
    if filtered.empty:
        st.info("No victims match the selected escalation levels.")
        return

    st.markdown(
        f"<div style='font-size:12px;color:#8b949e;margin:0 0 14px;'>"
        f"Showing <b style='color:#c9d1d9;'>{len(filtered)}</b> of "
        f"<b style='color:#c9d1d9;'>{len(scored)}</b> Malaysia victims</div>",
        unsafe_allow_html=True,
    )

    def _esc(val: str) -> str:
        """Escape special characters so they render safely inside HTML."""
        return (
            str(val)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )

    for _, row in filtered.iterrows():
        lvl      = row["escalation_level"]
        meta     = LEVELS[lvl]
        triggers = row.get("escalation_triggers", "")

        # Sanitise every value before putting it into HTML
        org          = _esc(row.get("organization", "Unknown Victim") or "Unknown Victim")
        sector       = _esc(row.get("sector",       "—") or "—")
        threat_actor = _esc(row.get("threat_actor", "Unknown") or "Unknown")
        date_val     = row.get("date", pd.NaT)

        date_str      = "—"
        recency_badge = ""
        if pd.notna(date_val):
            try:
                dt       = pd.to_datetime(date_val, utc=True).tz_convert(TZ_MY)
                date_str = dt.strftime("%d %b %Y, %H:%M")
                hrs_ago  = (_now() - dt).total_seconds() / 3600
                if hrs_ago <= hours_threshold:
                    recency_badge = (
                        f"<span style=\"background:#1c3a1c;color:#3fb950;"
                        f"font-family:IBM Plex Mono,monospace;font-size:10px;"
                        f"font-weight:700;padding:2px 7px;border-radius:4px;"
                        f"letter-spacing:.06em;\">🕒 {int(hrs_ago)}h ago</span>"
                    )
            except Exception:
                pass

        # Trigger pills (only if toggle is on)
        trigger_html = ""
        if show_rules and triggers and triggers != "No rules fired":
            pills = "".join(
                f"<span style=\"background:#21262d;border:1px solid #30363d;"
                f"border-radius:4px;padding:2px 8px;font-size:10px;"
                f"font-family:IBM Plex Mono,monospace;color:#8b949e;"
                f"margin:2px 3px 2px 0;display:inline-block;\">{_esc(t.strip())}</span>"
                for t in triggers.split("|") if t.strip()
            )
            trigger_html = (
                "<div style=\"margin-top:8px;line-height:2;\">"
                "<span style=\"font-size:10px;color:#484f58;margin-right:4px;\">TRIGGERED:</span>"
                f"{pills}</div>"
            )

        # Escalation badge — use only known-safe values (no user data)
        badge_html = (
            f"<span style=\"background:{meta['bg']};color:{meta['color']};"
            f"border:1px solid {meta['border']};"
            f"font-family:IBM Plex Mono,monospace;font-size:11px;font-weight:700;"
            f"padding:3px 10px;border-radius:4px;letter-spacing:.06em;"
            f"text-transform:uppercase;\">{meta['emoji']} {lvl}</span>"
        )

        card_html = (
            f"<div style=\"background:#161b22;border:1px solid #21262d;"
            f"border-left:4px solid {meta['border']};"
            f"border-radius:8px;padding:14px 18px;margin-bottom:10px;\">"

            # ── Top row: org name + badges ──
            f"<div style=\"display:flex;align-items:center;"
            f"justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:8px;\">"
            f"<div style=\"font-size:15px;font-weight:600;color:#f0f6fc;\">{org}</div>"
            f"<div style=\"display:flex;align-items:center;gap:8px;\">"
            f"{recency_badge}{badge_html}"
            f"</div></div>"

            # ── Meta row: date · sector · severity · actor ──
            f"<div style=\"font-family:IBM Plex Mono,monospace;font-size:12px;"
            f"color:#8b949e;display:flex;flex-wrap:wrap;gap:0;align-items:center;\">"
            f"<span>📅 {date_str}</span>"
            f"<span style=\"color:#444d56;\">&nbsp;·&nbsp;</span>"
            f"<span>🏭 {sector}</span>"
            f"<span style=\"color:#444d56;\">&nbsp;·&nbsp;</span>"
            f"<span>🎭 Actor: <b style=\"color:#388bfd;\">{threat_actor}</b></span>"
            f"</div>"

            # ── Triggered rules ──
            f"{trigger_html}"
            f"</div>"
        )

        st.markdown(card_html, unsafe_allow_html=True)

    # ── Raw table (optional) ──────────────────────────────────────────────────
    with st.expander("📊 View full escalation table"):
        show_cols = ["escalation_level", "organization", "sector",
                     "threat_actor", "severity", "date", "escalation_triggers"]
        show_cols = [c for c in show_cols if c in filtered.columns]
        st.dataframe(
            filtered[show_cols],
            use_container_width=True,
            hide_index=True,
            column_config={
                "escalation_level": st.column_config.TextColumn("Level"),
                "escalation_triggers": st.column_config.TextColumn(
                    "Triggered Rules", width="large"
                ),
            },
        )