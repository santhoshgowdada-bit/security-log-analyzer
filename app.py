"""
Security Log Analyzer - Professional SOC Security Monitoring Dashboard
A modern, dark cybersecurity interface for analyzing authentication logs,
detecting threats, investigating suspicious IPs, and generating reports.
"""

import streamlit as st
import sys
import os
import io
import re
import json
import sqlite3
import pandas as pd
import time
from datetime import datetime

# Optional Plotly for SOC Interactive Visualizations
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False


# ============================================================
# PROJECT MODULES & BACKEND PRESERVATION
# ============================================================

SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SRC_DIR)
if SRC_DIR not in sys.path:
    sys.path.append(SRC_DIR)

from parser import parse_logs
from detector import detect_bruteforce, detect_multiple_accounts
from database import save_alert


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Security Log Analyzer | SOC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


# ============================================================
# MODERN SOC CYBERSECURITY THEME (CUSTOM CSS)
# ============================================================

THEME_PALETTES = {
    "🛡️ Deep Navy SOC (Standard)": {
        "name": "Deep Navy SOC",
        "bg_base": "#0B1220",
        "bg_gradient": "radial-gradient(ellipse 90% 60% at 50% -20%, rgba(34, 211, 238, 0.12), transparent), radial-gradient(ellipse 60% 40% at 85% 90%, rgba(59, 130, 246, 0.08), transparent), #0B1220",
        "bg_sidebar": "#0D1627",
        "bg_sidebar_card": "rgba(17, 28, 46, 0.85)",
        "bg_panel": "#111C2E",
        "bg_panel_secondary": "#18263E",
        "bg_panel_hover": "#1F314F",
        "border_default": "rgba(34, 211, 238, 0.18)",
        "border_hover": "rgba(34, 211, 238, 0.45)",
        "border_glow": "0 0 15px rgba(34, 211, 238, 0.20)",
        "accent_primary": "#22D3EE",
        "accent_cyan": "#22D3EE",
        "accent_indigo": "#3B82F6",
        "color_danger": "#EF4444",
        "color_danger_bg": "rgba(239, 68, 68, 0.14)",
        "color_danger_border": "rgba(239, 68, 68, 0.38)",
        "color_success": "#22C55E",
        "color_success_bg": "rgba(34, 197, 94, 0.14)",
        "color_success_border": "rgba(34, 197, 94, 0.38)",
        "color_warning": "#F59E0B",
        "color_warning_bg": "rgba(245, 158, 11, 0.14)",
        "color_warning_border": "rgba(245, 158, 11, 0.38)",
        "text_primary": "#E5E7EB",
        "text_secondary": "#CBD5E1",
        "text_muted": "#94A3B8",
        "chart_box_bg": "linear-gradient(180deg, #111C2E 0%, #0B1220 100%)",
        "plotly_plot": "rgba(11, 18, 32, 0.6)",
    },
    "🌌 Cyber Midnight (Neon Cyan & Ruby)": {
        "name": "Cyber Midnight",
        "bg_base": "#06090F",
        "bg_gradient": "radial-gradient(ellipse 90% 60% at 50% -20%, rgba(56, 189, 248, 0.12), transparent), radial-gradient(ellipse 60% 40% at 85% 90%, rgba(99, 102, 241, 0.08), transparent), #06090F",
        "bg_sidebar": "#090D16",
        "bg_sidebar_card": "rgba(13, 21, 36, 0.85)",
        "bg_panel": "#0D1524",
        "bg_panel_secondary": "#132035",
        "bg_panel_hover": "#1A2B45",
        "border_default": "rgba(56, 189, 248, 0.16)",
        "border_hover": "rgba(56, 189, 248, 0.38)",
        "border_glow": "0 0 15px rgba(56, 189, 248, 0.18)",
        "accent_primary": "#00F0FF",
        "accent_cyan": "#38BDF8",
        "accent_indigo": "#6366F1",
        "color_danger": "#F43F5E",
        "color_danger_bg": "rgba(244, 63, 94, 0.14)",
        "color_danger_border": "rgba(244, 63, 94, 0.38)",
        "color_success": "#10B981",
        "color_success_bg": "rgba(16, 185, 129, 0.14)",
        "color_success_border": "rgba(16, 185, 129, 0.38)",
        "color_warning": "#F59E0B",
        "color_warning_bg": "rgba(245, 158, 11, 0.14)",
        "color_warning_border": "rgba(245, 158, 11, 0.38)",
        "text_primary": "#F8FAFC",
        "text_secondary": "#94A3B8",
        "text_muted": "#64748B",
        "chart_box_bg": "linear-gradient(180deg, #0D1524 0%, #090D16 100%)",
        "plotly_plot": "rgba(6, 9, 15, 0.6)",
    },
    "🔷 Deep Ocean Sapphire": {
        "name": "Deep Ocean Sapphire",
        "bg_base": "#050C1A",
        "bg_gradient": "radial-gradient(ellipse 90% 60% at 40% -10%, rgba(37, 99, 235, 0.18), transparent), radial-gradient(ellipse 60% 40% at 85% 85%, rgba(6, 182, 212, 0.10), transparent), #050C1A",
        "bg_sidebar": "#081326",
        "bg_sidebar_card": "rgba(11, 29, 56, 0.85)",
        "bg_panel": "#0B1D38",
        "bg_panel_secondary": "#11294C",
        "bg_panel_hover": "#173663",
        "border_default": "rgba(96, 165, 250, 0.22)",
        "border_hover": "rgba(96, 165, 250, 0.50)",
        "border_glow": "0 0 15px rgba(37, 99, 235, 0.25)",
        "accent_primary": "#38BDF8",
        "accent_cyan": "#60A5FA",
        "accent_indigo": "#3B82F6",
        "color_danger": "#FB7185",
        "color_danger_bg": "rgba(251, 113, 133, 0.14)",
        "color_danger_border": "rgba(251, 113, 133, 0.40)",
        "color_success": "#06D6A0",
        "color_success_bg": "rgba(6, 214, 160, 0.14)",
        "color_success_border": "rgba(6, 214, 160, 0.40)",
        "color_warning": "#FBBF24",
        "color_warning_bg": "rgba(251, 191, 36, 0.14)",
        "color_warning_border": "rgba(251, 191, 36, 0.40)",
        "text_primary": "#F0F6FC",
        "text_secondary": "#93C5FD",
        "text_muted": "#64748B",
        "chart_box_bg": "linear-gradient(180deg, #0B1D38 0%, #071328 100%)",
        "plotly_plot": "rgba(5, 12, 26, 0.6)",
    },
    "🟣 Royal Obsidian Amethyst": {
        "name": "Royal Obsidian Amethyst",
        "bg_base": "#0B0714",
        "bg_gradient": "radial-gradient(ellipse 90% 60% at 50% -20%, rgba(168, 85, 247, 0.16), transparent), radial-gradient(ellipse 60% 40% at 85% 85%, rgba(236, 72, 153, 0.11), transparent), #0B0714",
        "bg_sidebar": "#100B1E",
        "bg_sidebar_card": "rgba(23, 16, 42, 0.85)",
        "bg_panel": "#17102A",
        "bg_panel_secondary": "#22183D",
        "bg_panel_hover": "#2E2151",
        "border_default": "rgba(192, 132, 252, 0.22)",
        "border_hover": "rgba(192, 132, 252, 0.50)",
        "border_glow": "0 0 15px rgba(168, 85, 247, 0.25)",
        "accent_primary": "#C084FC",
        "accent_cyan": "#A855F7",
        "accent_indigo": "#8B5CF6",
        "color_danger": "#F43F5E",
        "color_danger_bg": "rgba(244, 63, 94, 0.14)",
        "color_danger_border": "rgba(244, 63, 94, 0.40)",
        "color_success": "#34D399",
        "color_success_bg": "rgba(52, 211, 153, 0.14)",
        "color_success_border": "rgba(52, 211, 153, 0.40)",
        "color_warning": "#FBBF24",
        "color_warning_bg": "rgba(251, 191, 36, 0.14)",
        "color_warning_border": "rgba(251, 191, 36, 0.40)",
        "text_primary": "#FAF5FF",
        "text_secondary": "#D8B4FE",
        "text_muted": "#8A79A8",
        "chart_box_bg": "linear-gradient(180deg, #17102A 0%, #100B1E 100%)",
        "plotly_plot": "rgba(11, 7, 20, 0.6)",
    },
    "🟢 Stealth Emerald Matrix": {
        "name": "Stealth Emerald Matrix",
        "bg_base": "#050F0A",
        "bg_gradient": "radial-gradient(ellipse 90% 60% at 50% -20%, rgba(16, 185, 129, 0.16), transparent), radial-gradient(ellipse 60% 40% at 85% 85%, rgba(20, 184, 166, 0.10), transparent), #050F0A",
        "bg_sidebar": "#091710",
        "bg_sidebar_card": "rgba(13, 34, 24, 0.85)",
        "bg_panel": "#0D2218",
        "bg_panel_secondary": "#133123",
        "bg_panel_hover": "#1A412F",
        "border_default": "rgba(52, 211, 153, 0.22)",
        "border_hover": "rgba(52, 211, 153, 0.50)",
        "border_glow": "0 0 15px rgba(16, 185, 129, 0.25)",
        "accent_primary": "#34D399",
        "accent_cyan": "#10B981",
        "accent_indigo": "#14B8A6",
        "color_danger": "#F87171",
        "color_danger_bg": "rgba(248, 113, 113, 0.14)",
        "color_danger_border": "rgba(248, 113, 113, 0.40)",
        "color_success": "#10B981",
        "color_success_bg": "rgba(16, 185, 129, 0.15)",
        "color_success_border": "rgba(16, 185, 129, 0.40)",
        "color_warning": "#FBBF24",
        "color_warning_bg": "rgba(251, 191, 36, 0.14)",
        "color_warning_border": "rgba(251, 191, 36, 0.40)",
        "text_primary": "#ECFDF5",
        "text_secondary": "#A7F3D0",
        "text_muted": "#5E8E75",
        "chart_box_bg": "linear-gradient(180deg, #0D2218 0%, #081710 100%)",
        "plotly_plot": "rgba(5, 15, 10, 0.6)",
    },
    "💎 Titanium Slate (High Contrast)": {
        "name": "Titanium Slate",
        "bg_base": "#0B0F19",
        "bg_gradient": "radial-gradient(ellipse 90% 60% at 50% -20%, rgba(56, 189, 248, 0.14), transparent), #0B0F19",
        "bg_sidebar": "#101624",
        "bg_sidebar_card": "rgba(20, 27, 43, 0.85)",
        "bg_panel": "#151E30",
        "bg_panel_secondary": "#1C273E",
        "bg_panel_hover": "#24324F",
        "border_default": "rgba(148, 163, 184, 0.22)",
        "border_hover": "rgba(56, 189, 248, 0.45)",
        "border_glow": "0 0 15px rgba(56, 189, 248, 0.18)",
        "accent_primary": "#38BDF8",
        "accent_cyan": "#38BDF8",
        "accent_indigo": "#818CF8",
        "color_danger": "#EF4444",
        "color_danger_bg": "rgba(239, 68, 68, 0.14)",
        "color_danger_border": "rgba(239, 68, 68, 0.38)",
        "color_success": "#22C55E",
        "color_success_bg": "rgba(34, 197, 94, 0.14)",
        "color_success_border": "rgba(34, 197, 94, 0.38)",
        "color_warning": "#F59E0B",
        "color_warning_bg": "rgba(245, 158, 11, 0.14)",
        "color_warning_border": "rgba(245, 158, 11, 0.38)",
        "text_primary": "#F8FAFC",
        "text_secondary": "#CBD5E1",
        "text_muted": "#64748B",
        "chart_box_bg": "linear-gradient(180deg, #151E30 0%, #0F1625 100%)",
        "plotly_plot": "rgba(11, 15, 25, 0.6)",
    }
}


def generate_soc_css(theme_key="🛡️ Deep Navy SOC (Standard)") -> str:
    """Generate dynamic CSS styles matching the selected cyber theme."""
    t = THEME_PALETTES.get(theme_key, THEME_PALETTES["🛡️ Deep Navy SOC (Standard)"])
    return f"""
<style>
/* ── Offline-first typography fallbacks ── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

/* ── CSS Variables ── */
:root {{
    --bg-base: {t['bg_base']};
    --bg-panel: {t['bg_panel']};
    --bg-panel-secondary: {t['bg_panel_secondary']};
    --bg-panel-hover: {t['bg_panel_hover']};
    --border-default: {t['border_default']};
    --border-hover: {t['border_hover']};
    --text-primary: {t['text_primary']};
    --text-secondary: {t['text_secondary']};
    --text-muted: {t['text_muted']};
    --accent-primary: {t['accent_primary']};
    --accent-cyan: {t['accent_cyan']};
    --accent-indigo: {t['accent_indigo']};
    --color-success: {t['color_success']};
    --color-warning: {t['color_warning']};
    --color-danger: {t['color_danger']};
}}

/* ── Box-sizing & Smooth Scroll for Laptop Viewport ── */
*, *::before, *::after {{
    box-sizing: border-box !important;
}}
html {{
    scroll-behavior: smooth !important;
}}
body, .stApp, [data-testid="stAppViewContainer"] {{
    overflow-x: hidden !important;
}}
.block-container {{
    padding-top: 1.1rem !important;
    padding-bottom: 2.2rem !important;
    padding-left: 1.4rem !important;
    padding-right: 1.4rem !important;
    max-width: 100% !important;
}}
[id^="sec-"], .soc-anchor {{
    scroll-margin-top: 20px !important;
}}

/* ── Global App Canvas ── */
.stApp {{
    background: {t['bg_gradient']} !important;
    background-attachment: fixed !important;
    color: var(--text-primary);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}}

/* ── Sidebar (Compact Laptop Fit) ── */
[data-testid="stSidebar"] {{
    background-color: {t['bg_sidebar']} !important;
    border-right: 1px solid var(--border-default) !important;
    min-width: 275px !important;
}}
[data-testid="stSidebar"] > div:first-child {{
    padding: 1rem 0.85rem !important;
}}
[data-testid="stSidebar"] hr {{
    border-color: var(--border-default) !important;
    margin: 10px 0 !important;
}}
[data-testid="stSidebar"] .stRadio > div {{
    gap: 2px !important;
}}
[data-testid="stSidebar"] .stRadio label {{
    padding: 6px 10px !important;
    border-radius: 6px !important;
    transition: all 0.15s ease !important;
    font-size: 0.82rem !important;
    color: var(--text-secondary) !important;
}}
[data-testid="stSidebar"] .stRadio label:hover {{
    background: var(--bg-panel-hover) !important;
    color: var(--text-primary) !important;
}}

/* ── Header Banner ── */
.soc-header {{
    background: linear-gradient(135deg, {t['bg_panel']} 0%, {t['bg_panel_secondary']} 100%);
    border: 1px solid var(--border-default);
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 16px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4), {t['border_glow']};
    position: relative;
    overflow: hidden;
    gap: 12px;
    flex-wrap: wrap;
}}
.soc-header::after {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, transparent, {t['accent_primary']}, transparent);
}}
.soc-header-title {{
    font-size: 1.35rem;
    font-weight: 800;
    letter-spacing: -0.02em;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
}}
.soc-header-badge {{
    background: rgba(34, 211, 238, 0.14);
    border: 1px solid {t['accent_primary']};
    color: {t['accent_primary']};
    font-size: 0.68rem;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 9999px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}}
.soc-header-sub {{
    color: var(--text-secondary);
    font-size: 0.80rem;
    margin-top: 3px;
}}

/* ── KPI Cards Grid (Laptop Responsive) ── */
.kpi-grid {{
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
    margin-bottom: 12px;
}}
@media (max-width: 1100px) {{
    .kpi-grid {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
}}
@media (max-width: 580px) {{
    .kpi-grid {{ grid-template-columns: 1fr; }}
}}
.kpi-card {{
    background: linear-gradient(145deg, {t['bg_panel']} 0%, {t['bg_panel_secondary']} 100%) !important;
    border: 1px solid var(--border-default) !important;
    border-radius: 10px !important;
    padding: 12px 14px !important;
    position: relative !important;
    overflow: hidden !important;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35) !important;
    min-width: 0 !important;
    transition: transform 0.2s ease, border-color 0.2s ease !important;
}}
.kpi-card:hover {{
    transform: translateY(-2px) !important;
    border-color: var(--border-hover) !important;
}}
.kpi-card::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, transparent, {t['accent_primary']}, transparent);
}}
.kpi-label {{
    font-size: 0.68rem !important;
    font-weight: 700 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.06em !important;
    color: var(--text-secondary) !important;
    margin-bottom: 4px !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
}}
.kpi-value {{
    font-size: 1.55rem !important;
    font-weight: 800 !important;
    font-family: 'JetBrains Mono', 'Inter', monospace !important;
    letter-spacing: -0.02em !important;
    line-height: 1.15 !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
}}
.kpi-sub {{
    font-size: 0.68rem !important;
    color: var(--text-muted) !important;
    margin-top: 3px !important;
    white-space: nowrap !important;
    overflow: hidden !important;
    text-overflow: ellipsis !important;
}}

/* ── SOC Section Headings ── */
.soc-section-heading {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 16px;
    background: linear-gradient(90deg, rgba(17, 28, 46, 0.95) 0%, rgba(11, 18, 32, 0.65) 100%);
    border: 1px solid var(--border-default);
    border-left: 4px solid {t['accent_primary']};
    border-radius: 8px;
    margin: 22px 0 12px 0;
    scroll-margin-top: 20px;
    gap: 10px;
    flex-wrap: wrap;
}}
.soc-section-heading-left {{
    display: flex;
    align-items: center;
    gap: 10px;
}}
.soc-section-icon {{
    font-size: 1.25rem;
}}
.soc-section-title {{
    font-size: 0.92rem;
    font-weight: 800;
    letter-spacing: 0.04em;
    color: #F8FAFC;
    text-transform: uppercase;
}}
.soc-section-desc {{
    font-size: 0.73rem;
    color: var(--text-secondary);
}}
.soc-section-tag {{
    font-size: 0.64rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    background: rgba(34, 211, 238, 0.12);
    color: {t['accent_primary']};
    border: 1px solid rgba(34, 211, 238, 0.3);
    text-transform: uppercase;
    letter-spacing: 0.04em;
}}

/* ── Quick Jump Nav Buttons ── */
.soc-jump-grid {{
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 5px;
    margin: 6px 0 10px 0;
}}
.soc-jump-btn {{
    display: block;
    padding: 5px 6px;
    border-radius: 6px;
    background: rgba(17, 28, 46, 0.65);
    border: 1px solid rgba(34, 211, 238, 0.15);
    color: #CBD5E1;
    font-size: 0.72rem;
    font-weight: 600;
    text-align: center;
    text-decoration: none !important;
    transition: all 0.15s ease;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}}
.soc-jump-btn:hover {{
    background: rgba(34, 211, 238, 0.15);
    border-color: {t['accent_primary']};
    color: {t['accent_primary']};
    text-decoration: none !important;
    transform: translateY(-1px);
}}

/* ── Accent top borders ── */
.kpi-cyan::before   {{ background: linear-gradient(90deg, transparent, {t['accent_cyan']}, transparent) !important; }}
.kpi-red::before    {{ background: linear-gradient(90deg, transparent, {t['color_danger']}, transparent) !important; }}
.kpi-green::before  {{ background: linear-gradient(90deg, transparent, {t['color_success']}, transparent) !important; }}
.kpi-amber::before  {{ background: linear-gradient(90deg, transparent, {t['color_warning']}, transparent) !important; }}
.kpi-indigo::before {{ background: linear-gradient(90deg, transparent, {t['accent_indigo']}, transparent) !important; }}

/* ── Section panels ── */
.soc-panel {{
    background: linear-gradient(145deg, {t['bg_panel']} 0%, {t['bg_panel_secondary']} 100%);
    border: 1px solid var(--border-default);
    border-radius: 12px;
    padding: 20px 22px;
    margin-bottom: 20px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
}}
.soc-panel-title {{
    font-size: 1.05rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 14px;
    display: flex;
    align-items: center;
    gap: 8px;
}}

/* ── Severity Badges ── */
.sev-badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 0.72rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}
.sev-high {{
    background: {t['color_danger_bg']};
    color: {t['color_danger']};
    border: 1px solid {t['color_danger_border']};
}}
.sev-medium {{
    background: {t['color_warning_bg']};
    color: {t['color_warning']};
    border: 1px solid {t['color_warning_border']};
}}
.sev-low {{
    background: rgba(59, 130, 246, 0.18);
    color: #93C5FD;
    border: 1px solid rgba(59, 130, 246, 0.4);
}}

/* ── File card ── */
.file-card {{
    background: var(--bg-panel);
    border: 1px solid var(--border-default);
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    transition: border-color 0.18s ease;
}}
.file-card:hover {{
    border-color: var(--border-hover);
}}
.file-card-name {{
    font-weight: 600;
    font-size: 0.9rem;
    color: var(--text-primary);
    font-family: 'JetBrains Mono', monospace;
}}
.file-card-meta {{
    font-size: 0.76rem;
    color: var(--text-secondary);
    display: flex;
    gap: 12px;
    margin-top: 3px;
}}
.file-badge {{
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 0.72rem;
    font-weight: 600;
}}
.file-badge-ok {{
    background: {t['color_success_bg']};
    color: {t['color_success']};
    border: 1px solid {t['color_success_border']};
}}
.file-badge-err {{
    background: {t['color_danger_bg']};
    color: {t['color_danger']};
    border: 1px solid {t['color_danger_border']};
}}

/* ── Empty state ── */
.empty-state {{
    text-align: center;
    padding: 48px 24px;
    background: linear-gradient(145deg, {t['bg_panel']} 0%, {t['bg_panel_secondary']} 100%);
    border: 1px dashed var(--border-default);
    border-radius: 14px;
    margin: 20px 0;
}}
.empty-state-icon {{ font-size: 2.4rem; margin-bottom: 12px; opacity: 0.8; }}
.empty-state-title {{ font-size: 1.15rem; font-weight: 700; color: var(--text-primary); margin-bottom: 6px; }}
.empty-state-sub {{ font-size: 0.85rem; color: var(--text-secondary); max-width: 480px; margin: 0 auto; line-height: 1.6; }}

/* ── Activity feed ── */
.feed-item {{
    padding: 10px 14px;
    border-left: 3px solid var(--border-default);
    background: var(--bg-panel);
    border-radius: 0 8px 8px 0;
    margin-bottom: 6px;
    font-size: 0.82rem;
    display: flex;
    align-items: center;
    gap: 10px;
    transition: all 0.15s ease;
}}
.feed-item:hover {{
    border-left-color: {t['accent_primary']};
    background: var(--bg-panel-hover);
}}
.feed-time {{
    color: {t['accent_cyan']};
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.73rem;
    font-weight: 600;
    white-space: nowrap;
}}

/* ── Rule cards ── */
.rule-card {{
    background: var(--bg-panel);
    border: 1px solid var(--border-default);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    transition: border-color 0.18s ease;
}}
.rule-card:hover {{
    border-color: var(--border-hover);
}}

/* ── Status pill ── */
.status-pill {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.75rem;
    font-weight: 600;
}}
.status-online {{
    background: {t['color_success_bg']};
    border: 1px solid {t['color_success_border']};
    color: {t['color_success']};
}}
.status-dot {{
    width: 7px; height: 7px;
    background-color: {t['color_success']};
    border-radius: 50%;
    box-shadow: 0 0 6px {t['color_success']};
}}

/* ── Info box for explanation pages ── */
.info-box {{
    background: var(--bg-panel);
    border: 1px solid var(--border-default);
    border-radius: 12px;
    padding: 22px 26px;
    color: #CBD5E1;
    font-size: 0.88rem;
    line-height: 1.65;
    margin-bottom: 16px;
}}
.info-box h3 {{
    font-size: 1.05rem;
    font-weight: 700;
    color: {t['accent_cyan']};
    margin: 16px 0 8px 0;
}}
.info-box h3:first-child {{ margin-top: 0; }}
.info-box ul {{ margin-left: 18px; }}
.info-box code {{
    background: rgba(56, 189, 248, 0.12);
    color: {t['accent_cyan']};
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.82rem;
}}

/* ── Footer ── */
.soc-footer {{
    border-top: 1px solid var(--border-default);
    margin-top: 36px;
    padding-top: 16px;
    display: flex;
    justify-content: space-between;
    font-size: 0.75rem;
    color: var(--text-muted);
}}

/* ── Alert row card ── */
.alert-row {{
    background: var(--bg-panel);
    border: 1px solid var(--border-default);
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 10px;
    transition: border-color 0.18s ease;
}}
.alert-row:hover {{
    border-color: var(--border-hover);
}}

/* ── Plotly chart dark overrides ── */
.stPlotlyChart {{
    border-radius: 10px;
    overflow: hidden;
}}

/* ── Workflow Step Cards ── */
.wf-step-container {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
    margin-bottom: 20px;
}}
@media (max-width: 900px) {{
    .wf-step-container {{ grid-template-columns: 1fr; }}
}}
.wf-step-card {{
    background: var(--bg-panel);
    border: 1px solid var(--border-default);
    border-radius: 10px;
    padding: 16px 18px;
    border-top: 3px solid {t['accent_primary']};
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
}}
.wf-step-num {{
    font-size: 0.72rem;
    font-weight: 800;
    color: {t['accent_primary']};
    font-family: 'JetBrains Mono', monospace;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 4px;
}}
.wf-step-title {{
    font-size: 0.95rem;
    font-weight: 700;
    color: var(--text-primary);
    margin-bottom: 6px;
}}
.wf-step-desc {{
    font-size: 0.80rem;
    color: var(--text-secondary);
    line-height: 1.5;
}}

/* ── Tabs styling ── */
.stTabs [data-baseweb="tab-list"] {{
    gap: 8px !important;
    background-color: rgba(0, 0, 0, 0.32) !important;
    padding: 6px 8px !important;
    border-radius: 12px !important;
    border: 1px solid var(--border-default) !important;
    margin-bottom: 18px !important;
}}
.stTabs [data-baseweb="tab"] {{
    background-color: transparent !important;
    border: 1px solid transparent !important;
    border-radius: 8px !important;
    color: var(--text-secondary) !important;
    padding: 8px 18px !important;
    font-weight: 600 !important;
    font-size: 0.86rem !important;
    transition: all 0.18s ease !important;
}}
.stTabs [data-baseweb="tab"]:hover {{
    color: var(--text-primary) !important;
    background: var(--bg-panel-hover) !important;
}}
.stTabs [aria-selected="true"] {{
    background: linear-gradient(135deg, {t['bg_panel_secondary']} 0%, {t['bg_panel']} 100%) !important;
    color: {t['accent_primary']} !important;
    border: 1px solid var(--border-hover) !important;
    box-shadow: 0 2px 12px rgba(0, 0, 0, 0.4), {t['border_glow']} !important;
}}
.stTabs [data-baseweb="tab-highlight"] {{
    background-color: transparent !important;
}}

/* ── Modern Chart Containers ── */
.chart-box {{
    background: {t['chart_box_bg']} !important;
    border: 1px solid var(--border-default) !important;
    border-radius: 12px !important;
    padding: 18px 20px 14px 20px !important;
    margin-bottom: 18px !important;
    box-shadow: 0 4px 22px rgba(0, 0, 0, 0.35) !important;
    transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
}}
.chart-box:hover {{
    border-color: var(--border-hover) !important;
    box-shadow: 0 6px 26px rgba(0, 0, 0, 0.45), {t['border_glow']} !important;
}}
.chart-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 6px;
    padding-bottom: 8px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}}
.chart-title {{
    font-size: 0.95rem;
    font-weight: 700;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 8px;
}}
.chart-badge {{
    font-size: 0.66rem;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 9999px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    background: rgba(56, 189, 248, 0.12);
    border: 1px solid rgba(56, 189, 248, 0.3);
    color: {t['accent_cyan']};
}}
.chart-badge-danger {{
    background: {t['color_danger_bg']};
    border: 1px solid {t['color_danger_border']};
    color: {t['color_danger']};
}}
.chart-badge-success {{
    background: {t['color_success_bg']};
    border: 1px solid {t['color_success_border']};
    color: {t['color_success']};
}}
.chart-desc {{
    font-size: 0.76rem;
    color: var(--text-secondary);
    margin-bottom: 10px;
}}

/* ── Modern Alert Banners ── */
.soc-alert-banner {{
    display: flex;
    align-items: center;
    gap: 14px;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 18px;
    backdrop-filter: blur(10px);
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
}}
.soc-alert-danger {{
    background: linear-gradient(135deg, {t['color_danger_bg']} 0%, rgba(0,0,0,0.3) 100%) !important;
    border: 1px solid {t['color_danger_border']} !important;
}}
.soc-alert-success {{
    background: linear-gradient(135deg, {t['color_success_bg']} 0%, rgba(0,0,0,0.3) 100%) !important;
    border: 1px solid {t['color_success_border']} !important;
}}

/* ── Modern Analysis Summary Container ── */
.soc-summary-container {{
    background: linear-gradient(145deg, {t['bg_panel']}, {t['bg_panel_secondary']});
    border: 1px solid var(--border-default);
    border-left: 4px solid {t['accent_primary']} !important;
    border-radius: 12px;
    padding: 16px 20px;
    margin-bottom: 20px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
}}
.soc-summary-tile {{
    background: rgba(0, 0, 0, 0.35);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 8px;
    padding: 10px 14px;
    transition: transform 0.2s ease, border-color 0.2s ease;
}}
.soc-summary-tile:hover {{
    transform: translateY(-2px);
    border-color: var(--border-hover);
}}
</style>
"""

current_theme_key = st.session_state.get("app_theme_choice", "🛡️ Deep Navy SOC (Standard)")
st.markdown(generate_soc_css(current_theme_key), unsafe_allow_html=True)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_database_path():
    """Return absolute path to the SQLite database."""
    return os.path.join(PROJECT_ROOT, "security_alerts.db")


def get_database_status():
    """Verify connectivity to SQLite security_alerts.db and fetch total count."""
    db_path = get_database_path()
    try:
        conn = sqlite3.connect(db_path, timeout=2)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM alerts")
        count = cur.fetchone()[0]
        conn.close()
        return True, count
    except Exception:
        return False, 0


def get_db_alerts():
    """Fetch all historical alerts from database."""
    db_path = get_database_path()
    try:
        conn = sqlite3.connect(db_path, timeout=2)
        cur = conn.cursor()
        cur.execute("SELECT id, alert_type, ip_address, count, severity, risk_score FROM alerts")
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception:
        return []


def detect_file_source(filename, content):
    """
    Inspect log file content to detect source format without modifying parser.
    Returns: (detected_source, is_supported, file_size_str, reason)
    """
    if not content or not content.strip():
        return "Empty File", False, "0 B", "File contains no data."

    size_bytes = len(content.encode("utf-8"))
    size_str = f"{size_bytes / 1024:.1f} KB" if size_bytes > 1024 else f"{size_bytes} B"

    clean = content.lstrip("\ufeff").strip()
    first_non_empty = ""
    for line in clean.splitlines():
        if line.strip():
            first_non_empty = line.strip()
            break

    first_lower = first_non_empty.lower()

    # Windows CSV
    if ("," in first_lower) and any(k in first_lower for k in ["eventid", "sourceip", "logontype", "event_id"]):
        return "Windows Security CSV", True, size_str, None

    # Windows Event Viewer Text
    if "TimeCreated" in clean and re.search(r"Id\s*:\s*\d+", clean):
        return "Windows Event Viewer Log", True, size_str, None

    # Linux / Kali SSH Log
    ssh_tokens = ["sshd", "sshd-session", "pam_unix", "invalid user", "failed password", "accepted password"]
    if any(any(tok in line.lower() for tok in ssh_tokens) for line in clean.splitlines()[:20]):
        return "Linux SSH Log (Syslog)", True, size_str, None

    # Pipe-delimited Standard Auth Log
    if "|" in first_non_empty and len(first_non_empty.split("|")) >= 5:
        return "Standard Auth Log (Pipe-delimited)", True, size_str, None

    # Fallback: try parsing a sample
    try:
        sample_logs = parse_logs(clean[:4000])
        if sample_logs:
            source = sample_logs[0].get("source") or "Standard Authentication Log"
            return source, True, size_str, None
    except Exception:
        pass

    return "Unknown Format", False, size_str, "Unrecognized format. Expected Windows CSV, Event Log, Linux SSH, or pipe-delimited format."


def severity_badge_html(severity):
    """Return HTML span for a severity badge."""
    s = severity.upper()
    if s == "HIGH":
        return '<span class="sev-badge sev-high">HIGH</span>'
    elif s == "MEDIUM":
        return '<span class="sev-badge sev-medium">MEDIUM</span>'
    else:
        return '<span class="sev-badge sev-low">LOW</span>'


def make_plotly_layout(height=320, show_legend=True, legend_orient="h", title=None):
    """Return a consistent dark SOC Plotly layout dict aligned with active theme."""
    theme_key = st.session_state.get("app_theme_choice", "🛡️ Deep Navy SOC (Standard)")
    t = THEME_PALETTES.get(theme_key, THEME_PALETTES["🛡️ Deep Navy SOC (Standard)"])
    layout = dict(
        template="plotly_dark",
        autosize=True,
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor=t.get("plotly_plot", "rgba(6, 9, 15, 0.55)"),
        margin=dict(l=18, r=18, t=30 if title else 16, b=26),
        height=height,
        font=dict(family="Inter, -apple-system, sans-serif", size=11, color=t.get("text_primary", "#F8FAFC")),
        showlegend=show_legend,
        hoverlabel=dict(
            bgcolor=t.get("bg_panel", "#0D1524"),
            bordercolor=t.get("accent_primary", "#00F0FF"),
            font=dict(family="Inter, sans-serif", size=11, color="#FFFFFF")
        ),
        xaxis=dict(
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.05)",
            linecolor=t.get("border_default", "rgba(56, 189, 248, 0.2)"),
            tickfont=dict(size=10, color=t.get("text_secondary", "#94A3B8"))
        ),
        yaxis=dict(
            showgrid=True,
            gridcolor="rgba(255, 255, 255, 0.05)",
            linecolor=t.get("border_default", "rgba(56, 189, 248, 0.2)"),
            tickfont=dict(size=10, color=t.get("text_secondary", "#94A3B8"))
        )
    )
    if title:
        layout["title"] = dict(
            text=f"<b>{title}</b>",
            font=dict(size=13, color=t.get("text_primary", "#F8FAFC"), family="Inter, sans-serif"),
            x=0.02, y=0.96
        )
    if show_legend:
        if legend_orient == "h":
            layout["legend"] = dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                font=dict(size=11, color=t.get("text_secondary", "#CBD5E1"))
            )
        else:
            layout["legend"] = dict(
                orientation="v",
                yanchor="middle",
                y=0.5,
                xanchor="left",
                x=1.02,
                font=dict(size=11, color=t.get("text_secondary", "#CBD5E1"))
            )
    return layout


def build_auth_timeline_figure(current_logs, height=330):
    """Build a modern spline area chart for authentication timeline."""
    if not PLOTLY_AVAILABLE:
        return None
    df_logs = pd.DataFrame(current_logs)
    if df_logs.empty or "timestamp" not in df_logs.columns:
        return None
    try:
        df_time = df_logs.copy()
        df_time["ts_clean"] = df_time["timestamp"].astype(str).str.strip()
        df_time = df_time[df_time["ts_clean"] != ""]
        if df_time.empty:
            return None

        grouped = df_time.groupby(["ts_clean", "status"]).size().unstack(fill_value=0)
        for col in ["SUCCESS", "FAILED"]:
            if col not in grouped.columns:
                grouped[col] = 0
        grouped = grouped.reset_index()

        fig = go.Figure()
        # Successful logins trace
        fig.add_trace(go.Scatter(
            x=grouped["ts_clean"], y=grouped["SUCCESS"],
            mode="lines+markers", name="Successful Logins",
            line=dict(color="#22C55E", width=3, shape="spline"),
            marker=dict(size=7, color="#22C55E", symbol="circle", line=dict(color="#0B1220", width=1.5)),
            fill="tozeroy", fillcolor="rgba(34, 197, 94, 0.12)",
            hovertemplate="<b>%{x}</b><br><span style='color:#22C55E;'>●</span> Successful: <b>%{y}</b><extra></extra>"
        ))
        # Failed logins trace
        fig.add_trace(go.Scatter(
            x=grouped["ts_clean"], y=grouped["FAILED"],
            mode="lines+markers", name="Failed Attempts",
            line=dict(color="#EF4444", width=3, shape="spline"),
            marker=dict(size=7, color="#EF4444", symbol="circle", line=dict(color="#0B1220", width=1.5)),
            fill="tozeroy", fillcolor="rgba(239, 68, 68, 0.18)",
            hovertemplate="<b>%{x}</b><br><span style='color:#EF4444;'>●</span> Failed: <b>%{y}</b><extra></extra>"
        ))
        layout = make_plotly_layout(height=height)
        layout["xaxis"]["tickangle"] = -25
        layout["xaxis"]["showspikes"] = True
        layout["xaxis"]["spikecolor"] = "#22D3EE"
        layout["xaxis"]["spikethickness"] = 1
        layout["yaxis"]["title"] = dict(text="Events", font=dict(size=11, color="#94A3B8"))
        fig.update_layout(**layout)
        return fig
    except Exception:
        return None


def build_severity_donut_figure(current_alerts, total_events, successful_logins, failed_logins, height=330):
    """Build high-contrast severity distribution donut chart."""
    if not PLOTLY_AVAILABLE:
        return None

    high_count = sum(1 for a in current_alerts if a.get("severity") == "HIGH")
    med_count = sum(1 for a in current_alerts if a.get("severity") == "MEDIUM")
    low_count = sum(1 for a in current_alerts if a.get("severity") == "LOW")
    total_alerts = len(current_alerts)

    if total_alerts > 0:
        counts = {}
        colors_map = {"High": "#EF4444", "Medium": "#F59E0B", "Low": "#3B82F6"}
        if high_count > 0: counts["High"] = high_count
        if med_count > 0: counts["Medium"] = med_count
        if low_count > 0: counts["Low"] = low_count

        labels = list(counts.keys())
        values = list(counts.values())
        colors = [colors_map.get(l, "#94A3B8") for l in labels]
        pulls = [0.05 if l == "High" else 0.0 for l in labels]

        fig = go.Figure(data=[go.Pie(
            labels=labels, values=values, hole=0.64,
            marker=dict(colors=colors, line=dict(color="#0B1220", width=2.5)),
            pull=pulls,
            textinfo="value+percent",
            hovertemplate="<b>%{label} Severity</b><br>Detections: <b>%{value}</b> (%{percent})<extra></extra>"
        )])
        center_text = f"<b>{total_alerts}</b><br><span style='font-size:10px;color:#EF4444;font-weight:700;letter-spacing:1px;'>THREATS</span>"
    else:
        fig = go.Figure(data=[go.Pie(
            labels=["Legitimate Traffic"], values=[max(1, total_events)], hole=0.64,
            marker=dict(colors=["#22C55E"], line=dict(color="#0B1220", width=2.5)),
            textinfo="none",
            hovertemplate="<b>Security Assessment</b><br>0 Threat Detections (Clean)<extra></extra>"
        )])
        center_text = "<b>0</b><br><span style='font-size:10px;color:#22C55E;font-weight:700;letter-spacing:1px;'>SECURE</span>"

    layout = make_plotly_layout(height=height)
    layout["annotations"] = [dict(
        text=center_text, x=0.5, y=0.5, font_size=18, showarrow=False, font_color="#FFFFFF"
    )]
    layout["legend"] = dict(orientation="h", yanchor="bottom", y=-0.12, xanchor="center", x=0.5)
    fig.update_layout(**layout)
    return fig


def build_auth_outcome_donut_figure(successful_logins, failed_logins, height=330):
    """Build Authentication Outcome Donut chart."""
    if not PLOTLY_AVAILABLE:
        return None
    total = successful_logins + failed_logins
    if total == 0:
        return None

    fail_rate = (failed_logins / total * 100) if total > 0 else 0
    fig = go.Figure(data=[go.Pie(
        labels=["Successful", "Failed"],
        values=[successful_logins, failed_logins],
        hole=0.62,
        marker=dict(colors=["#22C55E", "#EF4444"], line=dict(color="#0B1220", width=2.5)),
        textinfo="value+percent",
        hovertemplate="<b>%{label} Authentication</b><br>Events: <b>%{value}</b> (%{percent})<extra></extra>"
    )])
    center_color = "#EF4444" if fail_rate > 20 else "#22C55E"
    layout = make_plotly_layout(height=height)
    layout["annotations"] = [dict(
        text=f"<b>{fail_rate:.1f}%</b><br><span style='font-size:10px;color:{center_color};font-weight:700;letter-spacing:0.5px;'>FAILURE RATE</span>",
        x=0.5, y=0.5, font_size=17, showarrow=False, font_color="#FFFFFF"
    )]
    layout["legend"] = dict(orientation="h", yanchor="bottom", y=-0.12, xanchor="center", x=0.5)
    fig.update_layout(**layout)
    return fig


def build_suspicious_ips_bar_figure(current_logs, current_alerts, height=300):
    """Build horizontal styled bar chart for suspicious source IPs."""
    if not PLOTLY_AVAILABLE:
        return None

    failed_events = [l for l in current_logs if l.get("status") == "FAILED"]
    ip_fail_counts = {}
    ip_users_map = {}
    for evt in failed_events:
        ip = evt.get("ip") or evt.get("ip_address")
        u = evt.get("username")
        if ip and ip not in ("-", "", "None", "UNKNOWN"):
            ip_fail_counts[ip] = ip_fail_counts.get(ip, 0) + 1
            if u and u not in ("-", "", "UNKNOWN"):
                ip_users_map.setdefault(ip, set()).add(str(u))

    if not ip_fail_counts:
        return None

    sorted_items = sorted(ip_fail_counts.items(), key=lambda x: x[1], reverse=False)[-8:]
    ips = [item[0] for item in sorted_items]
    counts = [item[1] for item in sorted_items]

    alert_ips = set(a.get("ip") for a in current_alerts if a.get("ip"))
    bar_colors = ["#EF4444" if ip in alert_ips else "#FB7185" for ip in ips]

    custom_data = []
    for ip in ips:
        users = list(ip_users_map.get(ip, []))
        users_str = ", ".join(users[:3]) if users else "N/A"
        is_alerted = "CRITICAL (Alert Triggered)" if ip in alert_ips else "Suspicious Failures"
        custom_data.append([users_str, is_alerted])

    fig = go.Figure(data=[go.Bar(
        y=ips, x=counts, orientation="h",
        marker=dict(color=bar_colors, line=dict(color="rgba(255,255,255,0.12)", width=1)),
        text=[f"{c} fails" for c in counts],
        textposition="auto",
        customdata=custom_data,
        hovertemplate="<b>Host IP: %{y}</b><br>Failed Attempts: <b>%{x}</b><br>Status: %{customdata[1]}<br>Target Users: %{customdata[0]}<extra></extra>"
    )])
    layout = make_plotly_layout(height=height, show_legend=False)
    layout["xaxis"]["title"] = dict(text="Failed Attempts", font=dict(size=11, color="#94A3B8"))
    layout["yaxis"]["showgrid"] = False
    fig.update_layout(**layout)
    return fig


def build_targeted_users_bar_figure(current_logs, height=300):
    """Build grouped bar chart showing top targeted usernames (Failed vs Success)."""
    if not PLOTLY_AVAILABLE or not current_logs:
        return None

    user_stats = {}
    for l in current_logs:
        u = l.get("username")
        if u and str(u) not in ("-", "", "None", "UNKNOWN"):
            u_str = str(u)
            if u_str not in user_stats:
                user_stats[u_str] = {"FAILED": 0, "SUCCESS": 0}
            status = l.get("status")
            if status in ("FAILED", "SUCCESS"):
                user_stats[u_str][status] += 1

    if not user_stats:
        return None

    top_users = sorted(user_stats.items(), key=lambda x: x[1]["FAILED"] * 2 + x[1]["SUCCESS"], reverse=True)[:7]
    usernames = [item[0] for item in top_users]
    failed_vals = [item[1]["FAILED"] for item in top_users]
    success_vals = [item[1]["SUCCESS"] for item in top_users]

    fig = go.Figure()
    fig.add_trace(go.Bar(
        name="Failed Attempts", x=usernames, y=failed_vals,
        marker=dict(color="#EF4444", line=dict(color="rgba(255,255,255,0.1)", width=1)),
        text=[v if v > 0 else "" for v in failed_vals],
        textposition="auto",
        hovertemplate="<b>User: %{x}</b><br><span style='color:#EF4444;'>●</span> Failed Attempts: <b>%{y}</b><extra></extra>"
    ))
    fig.add_trace(go.Bar(
        name="Successful Logins", x=usernames, y=success_vals,
        marker=dict(color="#22C55E", line=dict(color="rgba(255,255,255,0.1)", width=1)),
        text=[v if v > 0 else "" for v in success_vals],
        textposition="auto",
        hovertemplate="<b>User: %{x}</b><br><span style='color:#22C55E;'>●</span> Successful: <b>%{y}</b><extra></extra>"
    ))
    layout = make_plotly_layout(height=height, show_legend=True)
    layout["barmode"] = "group"
    layout["yaxis"]["title"] = dict(text="Attempts", font=dict(size=11, color="#94A3B8"))
    layout["xaxis"]["showgrid"] = False
    fig.update_layout(**layout)
    return fig


def build_attack_types_bar_figure(current_alerts, height=280):
    """Build horizontal bar chart of triggered detection rules."""
    if not PLOTLY_AVAILABLE or not current_alerts:
        return None

    df_alerts = pd.DataFrame(current_alerts)
    if "alert_type" not in df_alerts.columns:
        return None

    atk_counts = df_alerts["alert_type"].value_counts().reset_index()
    atk_counts.columns = ["Alert Type", "Count"]

    fig = go.Figure(data=[go.Bar(
        y=atk_counts["Alert Type"], x=atk_counts["Count"], orientation="h",
        marker=dict(color="#F59E0B", line=dict(color="rgba(255,255,255,0.15)", width=1)),
        text=[f"{c} alert(s)" for c in atk_counts["Count"]],
        textposition="auto",
        hovertemplate="<b>Rule: %{y}</b><br>Trigger Count: <b>%{x}</b><extra></extra>"
    )])
    layout = make_plotly_layout(height=height, show_legend=False)
    layout["xaxis"]["title"] = dict(text="Alert Triggers", font=dict(size=11, color="#94A3B8"))
    layout["yaxis"]["showgrid"] = False
    fig.update_layout(**layout)
    return fig


def build_ip_distribution_donut_figure(current_logs, height=330):
    """Build Donut chart showing hostile source IP distribution."""
    if not PLOTLY_AVAILABLE or not current_logs:
        return None

    failed_events = [l for l in current_logs if l.get("status") == "FAILED"]
    ip_counts = {}
    for evt in failed_events:
        ip = evt.get("ip") or evt.get("ip_address")
        if ip and ip not in ("-", "", "None", "UNKNOWN"):
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    if not ip_counts:
        return None

    labels = list(ip_counts.keys())
    values = list(ip_counts.values())
    colors = ["#EF4444", "#F97316", "#F59E0B", "#22D3EE", "#8B5CF6", "#EC4899", "#22C55E"]

    fig = go.Figure(data=[go.Pie(
        labels=labels, values=values, hole=0.62,
        marker=dict(colors=colors, line=dict(color="#0B1220", width=2)),
        textinfo="label+percent",
        hovertemplate="<b>IP: %{label}</b><br>Failed Events: <b>%{value}</b> (%{percent})<extra></extra>"
    )])
    layout = make_plotly_layout(height=height)
    layout["annotations"] = [dict(
        text=f"<b>{len(ip_counts)}</b><br><span style='font-size:10px;color:#94A3B8;'>HOSTILE IPS</span>",
        x=0.5, y=0.5, font_size=17, showarrow=False, font_color="#FFFFFF"
    )]
    layout["legend"] = dict(orientation="h", yanchor="bottom", y=-0.12, xanchor="center", x=0.5)
    fig.update_layout(**layout)
    return fig


def build_threat_risk_gauge_figure(current_alerts, successful_logins, failed_logins, total_events, height=330):
    """Build an interactive radial threat risk posture gauge."""
    if not PLOTLY_AVAILABLE:
        return None

    high_count = sum(1 for a in current_alerts if a.get("severity") == "HIGH")
    med_count = sum(1 for a in current_alerts if a.get("severity") == "MEDIUM")

    if high_count > 0:
        score = min(100, 70 + (high_count * 10) + (med_count * 5))
    elif med_count > 0:
        score = min(69, 45 + (med_count * 10))
    elif total_events > 0 and failed_logins > 0:
        score = min(35, round((failed_logins / total_events) * 35))
    else:
        score = 0

    if score >= 70:
        bar_color = "#EF4444"
        posture_label = "CRITICAL THREAT"
    elif score >= 35:
        bar_color = "#F59E0B"
        posture_label = "ELEVATED RISK"
    else:
        bar_color = "#22C55E"
        posture_label = "NORMAL POSTURE"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number=dict(font=dict(size=38, color="#FFFFFF", family="Inter, sans-serif"), suffix="/100"),
        gauge=dict(
            axis=dict(range=[0, 100], tickwidth=1, tickcolor="#94A3B8", tickfont=dict(color="#94A3B8", size=10)),
            bar=dict(color=bar_color, thickness=0.75),
            bgcolor="rgba(11, 18, 32, 0.6)",
            borderwidth=1,
            bordercolor="rgba(56, 189, 248, 0.2)",
            steps=[
                dict(range=[0, 35], color="rgba(16, 185, 129, 0.16)"),
                dict(range=[35, 70], color="rgba(245, 158, 11, 0.16)"),
                dict(range=[70, 100], color="rgba(239, 68, 68, 0.22)")
            ],
            threshold=dict(
                line=dict(color="#EF4444", width=3),
                thickness=0.8,
                value=70
            )
        )
    ))

    layout = make_plotly_layout(height=height, show_legend=False)
    layout["annotations"] = [dict(
        text=f"<span style='font-size:12px;font-weight:700;color:{bar_color};letter-spacing:1px;'>● {posture_label}</span>",
        x=0.5, y=0.15, showarrow=False
    )]
    layout["margin"] = dict(l=30, r=30, t=30, b=25)
    fig.update_layout(**layout)
    return fig


def render_html_fallback_bars(title, data_dict, color="#38BDF8"):
    """HTML/CSS fallback bar list in case Plotly fails."""
    if not data_dict:
        st.markdown(f"<div style='color: #64748B; font-size: 0.82rem;'>No data available for {title}</div>", unsafe_allow_html=True)
        return
    max_val = max(data_dict.values()) if data_dict.values() else 1
    bars_html = ""
    for label, val in data_dict.items():
        pct = (val / max_val * 100) if max_val > 0 else 0
        bars_html += f"""
        <div style="margin-bottom: 8px;">
            <div style="display: flex; justify-content: space-between; font-size: 0.78rem; color: #CBD5E1; margin-bottom: 3px;">
                <span>{label}</span>
                <span style="font-weight: 700; color: #F8FAFC;">{val}</span>
            </div>
            <div style="background: rgba(255, 255, 255, 0.08); height: 10px; border-radius: 999px; overflow: hidden;">
                <div style="width: {pct}%; height: 100%; background: {color}; border-radius: 999px;"></div>
            </div>
        </div>
        """
    st.markdown(f"<div class='chart-box'><div style='font-size:0.88rem;font-weight:700;color:#F8FAFC;margin-bottom:10px;'>{title}</div>{bars_html}</div>", unsafe_allow_html=True)



def render_empty_state(icon, title, subtitle):
    """Render a consistent empty state card."""
    st.markdown(
        f"""
        <div class="empty-state">
            <div class="empty-state-icon">{icon}</div>
            <div class="empty-state-title">{title}</div>
            <div class="empty-state-sub">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True
    )


def alert_already_in_db(alert, existing_db_alerts):
    """
    Check if an alert with the same type, IP, count, severity and risk_score
    already exists in the database to avoid duplicates.
    """
    a_type = alert.get("alert_type")
    a_ip = alert.get("ip") or alert.get("ip_address")
    a_count = alert.get("failed_attempts") if alert.get("failed_attempts") is not None else alert.get("count")
    a_sev = alert.get("severity")
    a_risk = alert.get("risk_score")

    for row in existing_db_alerts:
        # row: (id, alert_type, ip_address, count, severity, risk_score)
        if (row[1] == a_type and
            row[2] == a_ip and
            row[3] == a_count and
            row[4] == a_sev and
            row[5] == a_risk):
            return True
    return False


# ============================================================
# SESSION STATE INITIALIZATION
# ============================================================

if "logs" not in st.session_state:
    st.session_state.logs = []

if "alerts" not in st.session_state:
    st.session_state.alerts = []

if "analyzed_files" not in st.session_state:
    st.session_state.analyzed_files = []

if "analyzed_file_details" not in st.session_state:
    st.session_state.analyzed_file_details = []

if "analysis_done" not in st.session_state:
    st.session_state.analysis_done = False

if "last_analysis_time" not in st.session_state:
    st.session_state.last_analysis_time = None

if "analysis_duration" not in st.session_state:
    st.session_state.analysis_duration = 0.0

if "unrecognized_lines" not in st.session_state:
    st.session_state.unrecognized_lines = 0

if "analysis_metrics" not in st.session_state:
    st.session_state.analysis_metrics = None


# ============================================================
# ANALYSIS ENGINE & WORKFLOW PIPELINE
# ============================================================

def run_analysis(parsed_logs, file_names, file_details, bf_threshold=None, ma_threshold=None):
    """Execute detection engine, store results, persist to DB without duplicates."""
    if bf_threshold is None:
        bf_threshold = st.session_state.get("bf_threshold", 5)
    if ma_threshold is None:
        ma_threshold = st.session_state.get("ma_threshold", 3)
    detected_alerts = []
    detected_alerts.extend(detect_bruteforce(parsed_logs, threshold=bf_threshold))
    detected_alerts.extend(detect_multiple_accounts(parsed_logs, threshold=ma_threshold))

    st.session_state.logs = parsed_logs
    st.session_state.alerts = detected_alerts
    st.session_state.analyzed_files = file_names
    st.session_state.analyzed_file_details = file_details
    st.session_state.analysis_done = True
    st.session_state.last_analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Persist only new, non-duplicate alerts to database
    existing_db = get_db_alerts()
    saved_count = 0
    for a in detected_alerts:
        if not alert_already_in_db(a, existing_db):
            try:
                save_alert(a)
                saved_count += 1
                existing_db.append((None, a.get("alert_type"), a.get("ip") or a.get("ip_address"), a.get("failed_attempts"), a.get("severity"), a.get("risk_score")))
            except Exception:
                pass

    successful_count = sum(1 for log in parsed_logs if log.get("status") == "SUCCESS")
    failed_count = sum(1 for log in parsed_logs if log.get("status") == "FAILED")
    high_alert_count = sum(1 for a in detected_alerts if a.get("severity") == "HIGH")
    unrec = sum(d.get("unparsed", 0) for d in file_details) if file_details else 0
    st.session_state.unrecognized_lines = unrec

    st.session_state.analysis_metrics = {
        "files_analyzed": len(file_names),
        "total_events": len(parsed_logs),
        "successful_logins": successful_count,
        "failed_logins": failed_count,
        "total_alerts": len(detected_alerts),
        "high_alerts": high_alert_count,
        "unrecognized_lines": unrec,
        "newly_saved_alerts": saved_count
    }

    return detected_alerts, saved_count


class LocalFileWrapper:
    """Wrapper to make a local file path behave like a Streamlit UploadedFile."""
    def __init__(self, name, filepath):
        self.name = name
        with open(filepath, "rb") as fp:
            self._data = fp.read()
        self._pos = 0

    @property
    def size(self):
        return len(self._data)

    def getvalue(self):
        return self._data

    def read(self, *args):
        if not args or args[0] is None or args[0] < 0:
            res = self._data[self._pos:]
            self._pos = len(self._data)
            return res
        n = args[0]
        res = self._data[self._pos:self._pos + n]
        self._pos += len(res)
        return res

    def seek(self, pos):
        self._pos = pos



STAGE_DEFINITIONS = [
    (1, "Initializing Analysis (Validating Uploaded File)", "Validating input buffers, database connectivity, and runtime environment."),
    (2, "Reading Uploaded Files & Log Entries", "Reading raw file content, checking byte sizes and character encodings."),
    (3, "Identifying Supported Log Formats", "Inspecting file structure, headers, and matching signatures."),
    (4, "Parsing and Normalizing Events", "Extracting timestamps, IPs, users, and mapping to unified schema."),
    (5, "Checking Failed Logins & Applying Detection Rules", "Evaluating brute-force (SEC-RUL-001) and multiple-account spray (SEC-RUL-002)."),
    (6, "Preparing Charts, Metrics & Alerts", "Persisting alerts to SQLite and calculating SOC metric summaries."),
    (7, "Analysis Completed (Finalizing Report)", "Finalizing pipeline results and rendering interactive dashboard.")
]


def render_progress_card(current_stage, pct, detail, elapsed):
    """Render a styled dark SOC progress box with stage checkmarks."""
    stage_rows = ""
    for num, title, _ in STAGE_DEFINITIONS:
        if num < current_stage:
            icon = '<span style="color: #4ADE80; font-weight: 700;">✓</span>'
            style = 'color: #4ADE80; font-size: 0.8rem; display: flex; align-items: center; gap: 8px;'
        elif num == current_stage:
            icon = '<span style="color: #38BDF8; font-weight: 700;">●</span>'
            style = 'color: #38BDF8; font-weight: 700; font-size: 0.8rem; display: flex; align-items: center; gap: 8px;'
        else:
            icon = '<span style="color: #64748B;">○</span>'
            style = 'color: #64748B; font-size: 0.8rem; display: flex; align-items: center; gap: 8px;'
        stage_rows += f'<div style="{style}">{icon} <span>Stage {num}: {title}</span></div>'

    html = (
        f'<div style="background: #111C2E; border: 1px solid rgba(56, 189, 248, 0.25); border-radius: 10px; padding: 20px 22px; margin: 14px 0;">'
        f'<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">'
        f'<div style="font-weight: 700; font-size: 0.96rem; color: #F8FAFC;">'
        f'⚡ Stage {current_stage} of 7: {STAGE_DEFINITIONS[current_stage-1][1]}'
        f'</div>'
        f'<div style="font-family: \'JetBrains Mono\', monospace; font-size: 0.82rem; color: #38BDF8; font-weight: 700;">'
        f'{pct}% · {elapsed:.1f}s'
        f'</div>'
        f'</div>'
        f'<div style="font-size: 0.84rem; color: #CBD5E1; margin-bottom: 14px; background: rgba(11, 18, 32, 0.6); padding: 8px 12px; border-radius: 6px; border-left: 3px solid #38BDF8;">'
        f'{detail}'
        f'</div>'
        f'<div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 4px; margin-top: 10px;">'
        f'{stage_rows}'
        f'</div>'
        f'</div>'
    )
    return html


def execute_analysis_workflow(files_input, ui_container, min_visible_duration=None, demo_mode=None, bf_threshold=None, ma_threshold=None):
    """
    Executes a structured 7-stage security log analysis workflow.
    Guarantees:
      - Visible pacing with meaningful stages (target 10-15s in demo mode, immediate in normal mode).
      - Never falsely claims parsing is ongoing when already completed.
      - Computes real metrics: files, total events, successes, failures, alerts, high alerts, unrecognized lines.
      - Handles invalid/unsupported files with honest error reporting without claiming success.
      - Deduplicates alerts before saving to SQLite.
    """
    if demo_mode is None:
        demo_mode = st.session_state.get("demo_mode", False)
    if bf_threshold is None:
        bf_threshold = st.session_state.get("bf_threshold", 5)
    if ma_threshold is None:
        ma_threshold = st.session_state.get("ma_threshold", 3)
    if min_visible_duration is None:
        min_visible_duration = 10.0 if demo_mode else 5.0

    step_delay = 0.9 if demo_mode else (0.05 if min_visible_duration < 2.0 else 0.5)
    start_time = time.time()

    # Stage 1: Initializing Analysis (Validating Uploaded File)
    ui_container.markdown(
        render_progress_card(1, 10, "Validating input buffers, database connectivity, and runtime environment...", time.time() - start_time),
        unsafe_allow_html=True
    )
    db_ok, db_count = get_database_status()
    time.sleep(step_delay)

    # Stage 2: Reading Uploaded Files & Log Entries
    ui_container.markdown(
        render_progress_card(2, 25, f"Reading {len(files_input)} input file(s), inspecting byte buffers and character encodings...", time.time() - start_time),
        unsafe_allow_html=True
    )
    raw_files = []
    for f in files_input:
        if hasattr(f, "read"):
            raw_bytes = f.read()
            f.seek(0)
            content = raw_bytes.decode("utf-8-sig", errors="ignore")
            fname = getattr(f, "name", "uploaded_file.log")
        elif isinstance(f, (str, os.PathLike)):
            fname = os.path.basename(str(f))
            with open(f, "rb") as fp:
                raw_bytes = fp.read()
            content = raw_bytes.decode("utf-8-sig", errors="ignore")
        elif isinstance(f, dict):
            fname = f.get("name", "uploaded_file.log")
            content = f.get("content", "")
        else:
            fname = getattr(f, "name", str(f))
            content = str(f)
        raw_files.append({"name": fname, "content": content})
    time.sleep(step_delay)

    # Stage 3: Identifying Supported Log Formats
    ui_container.markdown(
        render_progress_card(3, 42, "Inspecting file structures, headers, and matching known security log signatures...", time.time() - start_time),
        unsafe_allow_html=True
    )
    file_inspection = []
    for item in raw_files:
        src_name, is_valid, size_str, reason = detect_file_source(item["name"], item["content"])
        total_lines = len([l for l in item["content"].strip().splitlines() if l.strip()])
        if src_name == "Windows Security CSV":
            total_lines = max(0, total_lines - 1)
        file_inspection.append({
            "name": item["name"],
            "content": item["content"],
            "source": src_name,
            "is_valid": is_valid,
            "size": size_str,
            "reason": reason,
            "total_lines": total_lines
        })
    time.sleep(step_delay)

    valid_files = [f for f in file_inspection if f["is_valid"]]
    invalid_files = [f for f in file_inspection if not f["is_valid"]]

    # Error handling: If NO files have a supported format:
    if not valid_files:
        error_boxes = ""
        for inv in invalid_files:
            error_boxes += (
                f'<div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 14px 16px; margin-bottom: 10px;">'
                f'<div style="font-weight: 700; color: #F87171; font-size: 0.92rem; margin-bottom: 4px;">⚠️ {inv["name"]}</div>'
                f'<div style="font-size: 0.82rem; color: #CBD5E1; margin-bottom: 6px;">Problem: {inv["reason"] or "Unsupported log format"}</div>'
                f'<div style="font-size: 0.78rem; color: #94A3B8;">Parsed Events: <strong style="color: #EF4444;">0</strong> · Unrecognized Lines: <strong style="color: #EF4444;">{inv["total_lines"]}</strong></div>'
                f'</div>'
            )
        ui_container.markdown(
            f'<div class="soc-panel" style="border-left: 4px solid #EF4444; margin: 16px 0;">'
            f'<div style="font-weight: 700; color: #F87171; font-size: 1rem; margin-bottom: 8px;">Analysis Failed: No Supported Security Logs</div>'
            f'<div style="font-size: 0.84rem; color: #94A3B8; margin-bottom: 14px;">The uploaded files could not be recognized by the parser. Please upload supported security log files.</div>'
            f'{error_boxes}'
            f'<div style="font-size: 0.82rem; color: #38BDF8; margin-top: 8px;">Supported formats: Windows Security CSV, Windows Event Viewer Text, Linux/Kali SSH Syslog, Pipe-delimited Auth Log.</div>'
            f'</div>',
            unsafe_allow_html=True
        )
        return False

    # Stage 4: Parsing and Normalizing Events
    ui_container.markdown(
        render_progress_card(4, 62, f"Parsing {len(valid_files)} supported log file(s) and normalizing authentication event records...", time.time() - start_time),
        unsafe_allow_html=True
    )
    all_logs = []
    analyzed_details = []
    total_unparsed = 0

    for item in file_inspection:
        if item["is_valid"]:
            parsed = parse_logs(item["content"])
            unparsed = max(0, item["total_lines"] - len(parsed))
            total_unparsed += unparsed
            all_logs.extend(parsed)
            analyzed_details.append({
                "name": item["name"],
                "type": item["name"].rsplit(".", 1)[-1].upper() if "." in item["name"] else "LOG",
                "size": item["size"],
                "source": item["source"],
                "status": "Parsed" if len(parsed) > 0 else "Failed",
                "count": len(parsed),
                "unparsed": unparsed,
                "reason": item["reason"]
            })
        else:
            total_unparsed += item["total_lines"]
            analyzed_details.append({
                "name": item["name"],
                "type": item["name"].rsplit(".", 1)[-1].upper() if "." in item["name"] else "UNKNOWN",
                "size": item["size"],
                "source": item["source"],
                "status": "Failed",
                "count": 0,
                "unparsed": item["total_lines"],
                "reason": item["reason"]
            })
    time.sleep(step_delay)

    # Error handling: If 0 events were parsed across all files
    if not all_logs:
        ui_container.markdown(
            f'<div class="soc-panel" style="border-left: 4px solid #EF4444; margin: 16px 0;">'
            f'<div style="font-weight: 700; color: #F87171; font-size: 1rem; margin-bottom: 8px;">⚠️ Parsing Warning: 0 Events Extracted</div>'
            f'<div style="font-size: 0.84rem; color: #CBD5E1; margin-bottom: 12px;">The parser could not extract any authentication events from the selected file(s). All {total_unparsed} line(s) were unrecognized.</div>'
            f'<div style="font-size: 0.8rem; color: #38BDF8;">Please ensure your log files contain valid authentication records (e.g. Windows Event 4624/4625 or Linux SSH auth events).</div>'
            f'</div>',
            unsafe_allow_html=True
        )
        return False

    # Stage 5: Checking Failed Logins & Applying Detection Rules
    ui_container.markdown(
        render_progress_card(5, 78, f"Extracted {len(all_logs):,} events. Evaluating detection rules SEC-RUL-001 (Brute-Force, threshold={bf_threshold}) and SEC-RUL-002 (Account Spray, threshold={ma_threshold})...", time.time() - start_time),
        unsafe_allow_html=True
    )
    detected_alerts = []
    detected_alerts.extend(detect_bruteforce(all_logs, threshold=bf_threshold))
    detected_alerts.extend(detect_multiple_accounts(all_logs, threshold=ma_threshold))
    time.sleep(step_delay)

    # Stage 6: Preparing Charts, Metrics & Alerts
    ui_container.markdown(
        render_progress_card(6, 92, f"Generated {len(detected_alerts)} threat alert(s). Checking deduplication and persisting to SQLite...", time.time() - start_time),
        unsafe_allow_html=True
    )
    existing_db = get_db_alerts()
    saved_count = 0
    for a in detected_alerts:
        if not alert_already_in_db(a, existing_db):
            try:
                save_alert(a)
                saved_count += 1
                existing_db.append((None, a.get("alert_type"), a.get("ip") or a.get("ip_address"), a.get("failed_attempts"), a.get("severity"), a.get("risk_score")))
            except Exception:
                pass

    # Save real data to session state
    st.session_state.logs = all_logs
    st.session_state.alerts = detected_alerts
    st.session_state.analyzed_files = [f["name"] for f in valid_files]
    st.session_state.analyzed_file_details = analyzed_details
    st.session_state.analysis_done = True
    st.session_state.last_analysis_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state.unrecognized_lines = total_unparsed

    successful_count = sum(1 for log in all_logs if log.get("status") == "SUCCESS")
    failed_count = sum(1 for log in all_logs if log.get("status") == "FAILED")
    high_alert_count = sum(1 for a in detected_alerts if a.get("severity") == "HIGH")

    st.session_state.analysis_metrics = {
        "files_analyzed": len(valid_files),
        "total_events": len(all_logs),
        "successful_logins": successful_count,
        "failed_logins": failed_count,
        "total_alerts": len(detected_alerts),
        "high_alerts": high_alert_count,
        "unrecognized_lines": total_unparsed,
        "newly_saved_alerts": saved_count
    }

    # Stage 7: Analysis Completed (Finalizing Report)
    elapsed = time.time() - start_time
    completion_msg = (
        f"Processing completed in {elapsed:.1f}s. Extracted {len(all_logs):,} event(s), "
        f"generated {len(detected_alerts)} threat alert(s). Finalizing SOC report..."
    )
    if elapsed < min_visible_duration:
        remaining = min_visible_duration - elapsed
        ui_container.markdown(
            render_progress_card(7, 100, completion_msg, elapsed),
            unsafe_allow_html=True
        )
        time.sleep(remaining)
    else:
        ui_container.markdown(
            render_progress_card(7, 100, completion_msg, elapsed),
            unsafe_allow_html=True
        )
        time.sleep(0.3)

    st.session_state.analysis_duration = time.time() - start_time
    return True


def render_analysis_results_summary():
    """Display real metrics from analysis in a modern SOC panel."""
    if not st.session_state.get("analysis_done"):
        return

    metrics = st.session_state.get("analysis_metrics")
    current_logs = st.session_state.get("logs", [])
    current_alerts = st.session_state.get("alerts", [])

    if not metrics:
        successful_count = sum(1 for log in current_logs if log.get("status") == "SUCCESS")
        failed_count = sum(1 for log in current_logs if log.get("status") == "FAILED")
        high_alert_count = sum(1 for a in current_alerts if a.get("severity") == "HIGH")
        unrec = st.session_state.get("unrecognized_lines", 0)
        metrics = {
            "files_analyzed": len(st.session_state.get("analyzed_file_details", [])),
            "total_events": len(current_logs),
            "successful_logins": successful_count,
            "failed_logins": failed_count,
            "total_alerts": len(current_alerts),
            "high_alerts": high_alert_count,
            "unrecognized_lines": unrec,
        }

    duration = st.session_state.get("analysis_duration", 0.0)
    last_time = st.session_state.get("last_analysis_time", "Just now")
    unrecognized = metrics.get("unrecognized_lines", 0)

    # Check for any unparsed lines or failed files
    file_warnings = []
    for d in st.session_state.get("analyzed_file_details", []):
        if d.get("status") == "Failed":
            file_warnings.append(f"<b>{d['name']}</b>: Failed ({d.get('reason') or 'Unrecognized format'}) · 0 parsed, {d.get('unparsed', 0)} unrecognized lines")
        elif d.get("unparsed", 0) > 0:
            file_warnings.append(f"<b>{d['name']}</b>: {d.get('unparsed')} unrecognized lines out of {d.get('count', 0) + d.get('unparsed', 0)} lines")

    warn_html = ""
    if file_warnings:
        warn_items = "".join([f"<div style='font-size: 0.78rem; color: #F59E0B; margin-top: 4px;'>⚠️ {w}</div>" for w in file_warnings])
        warn_html = (
            f'<div style="background: rgba(245, 158, 11, 0.08); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 6px; padding: 10px 14px; margin-top: 12px;">'
            f'<div style="font-size: 0.76rem; font-weight: 700; color: #F59E0B; text-transform: uppercase; letter-spacing: 0.05em;">Log Ingestion & Parsing Notices</div>'
            f'{warn_items}'
            f'</div>'
        )

    theme_key = st.session_state.get("app_theme_choice", "🌌 Cyber Midnight (Neon Cyan & Ruby)")
    t = THEME_PALETTES.get(theme_key, THEME_PALETTES["🌌 Cyber Midnight (Neon Cyan & Ruby)"])
    t_pri = t["text_primary"]
    t_sec = t["text_secondary"]
    t_cyan = t["accent_cyan"]
    t_succ = t["color_success"]
    t_dang = t["color_danger"]
    t_warn = t["color_warning"]
    t_mut = t["text_muted"]
    alerts_color = t_dang if metrics["total_alerts"] > 0 else t_succ
    high_color = t_dang if metrics["high_alerts"] > 0 else t_succ
    unrec_color = t_warn if unrecognized > 0 else t_mut
    duration_text = f"Duration: <strong style='color: {t_cyan};'>{duration:.1f}s</strong> · " if duration > 0 else ""

    html = f"""
    <div class="soc-summary-container">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="font-weight: 700; color: {t_pri}; font-size: 0.98rem; display: flex; align-items: center; gap: 8px;">
                <span>📊</span> ANALYSIS RESULTS SUMMARY
            </div>
            <div style="color: {t_sec}; font-size: 0.78rem; font-family: 'JetBrains Mono', monospace;">
                {duration_text}Processed: {last_time}
            </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 10px; font-size: 0.84rem;">
            <div class="soc-summary-tile">
                <span style="color: {t_sec}; font-size: 0.7rem; text-transform: uppercase;">Files Analyzed</span><br>
                <strong style="color: {t_pri}; font-size: 1.15rem;">{metrics["files_analyzed"]}</strong>
            </div>
            <div class="soc-summary-tile">
                <span style="color: {t_sec}; font-size: 0.7rem; text-transform: uppercase;">Parsed Events</span><br>
                <strong style="color: {t_cyan}; font-size: 1.15rem;">{metrics["total_events"]:,}</strong>
            </div>
            <div class="soc-summary-tile">
                <span style="color: {t_sec}; font-size: 0.7rem; text-transform: uppercase;">Successful Auth</span><br>
                <strong style="color: {t_succ}; font-size: 1.15rem;">{metrics["successful_logins"]:,}</strong>
            </div>
            <div class="soc-summary-tile">
                <span style="color: {t_sec}; font-size: 0.7rem; text-transform: uppercase;">Failed Auth</span><br>
                <strong style="color: {t_dang}; font-size: 1.15rem;">{metrics["failed_logins"]:,}</strong>
            </div>
            <div class="soc-summary-tile">
                <span style="color: {t_sec}; font-size: 0.7rem; text-transform: uppercase;">Security Alerts</span><br>
                <strong style="color: {alerts_color}; font-size: 1.15rem;">{metrics["total_alerts"]}</strong>
            </div>
            <div class="soc-summary-tile">
                <span style="color: {t_sec}; font-size: 0.7rem; text-transform: uppercase;">High Severity</span><br>
                <strong style="color: {high_color}; font-size: 1.15rem;">{metrics["high_alerts"]}</strong>
            </div>
            <div class="soc-summary-tile">
                <span style="color: {t_sec}; font-size: 0.7rem; text-transform: uppercase;">Unrecognized</span><br>
                <strong style="color: {unrec_color}; font-size: 1.15rem;">{unrecognized:,} lines</strong>
            </div>
        </div>
        {warn_html}
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def render_upload_section(key_suffix=""):
    """Render file uploader, file inspection cards, and analyze button."""
    st.markdown("<div class='soc-panel-title'>📂 LOG INGESTION & UPLOAD</div>", unsafe_allow_html=True)
    st.markdown(
        '<div style="color: #94A3B8; font-size: 0.88rem; margin-bottom: 14px;">'
        'Upload supported security logs (<code>.log</code>, <code>.txt</code>, <code>.csv</code>) to extract events and detect authentication threats.'
        '</div>',
        unsafe_allow_html=True
    )

    uploaded_files = st.file_uploader(
        "Upload Security Log Files (.log, .txt, .csv)",
        type=["log", "txt", "csv"],
        accept_multiple_files=True,
        key=f"file_uploader_{key_suffix}",
        help="Supports: Windows Security CSV, Windows Event Viewer Text Log, Linux/Kali SSH Syslog, Pipe-delimited Auth Logs."
    )

    if uploaded_files:
        st.markdown("<div style='font-weight: 600; font-size: 0.9rem; color: #E2E8F0; margin: 14px 0 8px 0;'>Uploaded File Inspection</div>", unsafe_allow_html=True)

        for ufile in uploaded_files:
            try:
                raw_bytes = ufile.read()
                ufile.seek(0)
                content = raw_bytes.decode("utf-8-sig", errors="ignore")
                src_name, is_valid, size_str, reason = detect_file_source(ufile.name, content)
                parsed_list = parse_logs(content) if is_valid else []

                total_lines = len([l for l in content.strip().splitlines() if l.strip()])
                if src_name == "Windows Security CSV":
                    total_lines = max(0, total_lines - 1)

                if is_valid and len(parsed_list) > 0:
                    badge_class = "file-badge-ok"
                    badge_text = f"Parsed successfully · {len(parsed_list)} events"
                elif is_valid:
                    badge_class = "file-badge-err"
                    badge_text = f"0 events parsed from {total_lines} lines"
                else:
                    badge_class = "file-badge-err"
                    badge_text = "File could not be parsed"

                reason_html = f"<div style='color: #F87171; font-size: 0.73rem; margin-top: 3px;'>Reason: {reason}</div>" if (reason and len(parsed_list) == 0) else ""
                unparsed = max(0, total_lines - len(parsed_list))
                unparsed_html = f" · {unparsed} lines unrecognized" if (unparsed > 0 and len(parsed_list) > 0) else ""

                card_html = (
                    f'<div class="file-card">'
                    f'<div>'
                    f'<div class="file-card-name">{ufile.name}</div>'
                    f'<div class="file-card-meta">'
                    f'<span>Type: <strong style="color: #CBD5E1;">{ufile.name.rsplit(".", 1)[-1].upper() if "." in ufile.name else "LOG"}</strong></span>'
                    f'<span>Size: <strong style="color: #CBD5E1;">{size_str}</strong></span>'
                    f'<span>Source: <strong style="color: #38BDF8;">{src_name}</strong></span>'
                    f'</div>'
                    f'{reason_html}'
                    f'</div>'
                    f'<span class="file-badge {badge_class}">{badge_text}{unparsed_html}</span>'
                    f'</div>'
                )
                st.markdown(card_html, unsafe_allow_html=True)

            except Exception as ex:
                st.error(f"Error reading {ufile.name}: {ex}")

        prog_box = st.empty()
        if st.button("🔍 Analyze Security Logs", type="primary", use_container_width=True, key=f"btn_analyze_{key_suffix}"):
            is_demo = st.session_state.get("demo_mode", True)
            min_dur = 10.0 if is_demo else 0.2
            bf_thresh = st.session_state.get("bf_threshold", 5)
            ma_thresh = st.session_state.get("ma_threshold", 3)
            success = execute_analysis_workflow(
                uploaded_files, prog_box,
                min_visible_duration=min_dur,
                demo_mode=is_demo,
                bf_threshold=bf_thresh,
                ma_threshold=ma_thresh
            )
            if success:
                st.rerun()

    else:
        st.info("📂 Drag and drop security log files above or click Browse files to begin analysis.")


# ============================================================
# MODULAR SECTION RENDERERS (RESPONSIVE & REUSABLE)
# ============================================================

def render_header_banner(db_connected, db_record_count):
    """Renders top SOC header banner with system and DB status."""
    last_time_html = ""
    if st.session_state.last_analysis_time:
        last_time_html = f'<div style="font-size: 0.76rem; color: #94A3B8; margin-top: 2px;">Last analysis: {st.session_state.last_analysis_time}</div>'

    db_pill_color = "#22C55E" if db_connected else "#EF4444"
    db_pill_text = "DB CONNECTED" if db_connected else "DB OFFLINE"

    header_html = (
        '<div id="sec-overview" class="soc-header">'
        '<div>'
        '<div class="soc-header-title">SECURITY OPERATIONS CENTER <span class="soc-header-badge">Log Analyzer</span></div>'
        '<div class="soc-header-sub">Analyze security events, investigate suspicious activity and monitor authentication threats.</div>'
        + last_time_html +
        '</div>'
        '<div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">'
        '<span class="status-pill status-online"><span class="status-dot"></span>SYSTEM ONLINE</span>'
        f'<span class="status-pill" style="background: rgba(34, 211, 238, 0.12); border: 1px solid rgba(34, 211, 238, 0.3); color: {db_pill_color}; font-size: 0.72rem; font-weight: 700;">● {db_pill_text} ({db_record_count})</span>'
        '</div>'
        '</div>'
    )
    st.markdown(header_html, unsafe_allow_html=True)


def render_kpi_cards_section(total_events, failed_logins, successful_logins, total_alerts, high_alerts, unique_ips_count, files_analyzed, parsing_rate):
    """Renders 8 responsive KPI cards in 2 rows."""
    st.markdown("<div id='sec-kpis' class='soc-anchor'></div>", unsafe_allow_html=True)
    st.markdown(
        f"""
        <div class="kpi-grid">
            <div class="kpi-card kpi-cyan">
                <div class="kpi-label">Total Events</div>
                <div class="kpi-value" style="color: var(--text-primary);">{total_events:,}</div>
                <div class="kpi-sub">Parsed authentication events</div>
            </div>
            <div class="kpi-card kpi-red">
                <div class="kpi-label">Failed Logins</div>
                <div class="kpi-value" style="color: {'var(--color-danger)' if failed_logins > 0 else 'var(--text-muted)'};">{failed_logins:,}</div>
                <div class="kpi-sub">Authentication rejections</div>
            </div>
            <div class="kpi-card kpi-green">
                <div class="kpi-label">Successful Logins</div>
                <div class="kpi-value" style="color: var(--color-success);">{successful_logins:,}</div>
                <div class="kpi-sub">Authorized sessions</div>
            </div>
            <div class="kpi-card kpi-red">
                <div class="kpi-label">Security Alerts</div>
                <div class="kpi-value" style="color: {'var(--color-danger)' if total_alerts > 0 else 'var(--text-muted)'};">{total_alerts:,}</div>
                <div class="kpi-sub">Detection rule triggers</div>
            </div>
        </div>
        <div class="kpi-grid">
            <div class="kpi-card kpi-red">
                <div class="kpi-label">High-Risk Alerts</div>
                <div class="kpi-value" style="color: {'var(--color-danger)' if high_alerts > 0 else 'var(--text-muted)'};">{high_alerts:,}</div>
                <div class="kpi-sub">Brute-force detections</div>
            </div>
            <div class="kpi-card kpi-amber">
                <div class="kpi-label">Unique Source IPs</div>
                <div class="kpi-value" style="color: {'var(--color-warning)' if unique_ips_count > 0 else 'var(--text-muted)'};">{unique_ips_count:,}</div>
                <div class="kpi-sub">Distinct source addresses</div>
            </div>
            <div class="kpi-card kpi-indigo">
                <div class="kpi-label">Files Analyzed</div>
                <div class="kpi-value" style="color: var(--accent-indigo);">{files_analyzed:,}</div>
                <div class="kpi-sub">Log files processed</div>
            </div>
            <div class="kpi-card kpi-cyan">
                <div class="kpi-label">Parsing Success Rate</div>
                <div class="kpi-value" style="color: {'var(--color-success)' if parsing_rate == 100 else 'var(--color-warning)'};">{parsing_rate:.0f}%</div>
                <div class="kpi-sub">Events successfully extracted</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


def render_latest_alerts_section(current_alerts, current_logs, total_events, high_alerts, medium_alerts, unique_ips_count, db_record_count, key_suffix="main"):
    """Renders Section 4: Latest Security Alerts with status banner, filters, and cards/table."""
    if not current_alerts:
        if total_events > 0:
            st.markdown(
                f"""
                <div class="soc-alert-banner soc-alert-success">
                    <div style="font-size: 1.6rem;">✅</div>
                    <div>
                        <div style="font-weight: 700; color: var(--color-success); font-size: 0.95rem; letter-spacing: 0.02em;">SECURITY ASSESSMENT: CLEAN</div>
                        <div style="color: var(--text-secondary); font-size: 0.84rem;">All {total_events:,} parsed events represent legitimate authentication activity. No detection rules triggered.</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            render_empty_state(
                "🛡️",
                "No Security Alerts Detected Yet",
                "Upload security log files above or click <b>🚨 Attack</b> / <b>📄 Clean</b> in the sidebar to populate alert analysis."
            )
        return

    # Threat banner
    st.markdown(
        f"""
        <div class="soc-alert-banner soc-alert-danger">
            <div style="font-size: 1.6rem;">🚨</div>
            <div>
                <div style="font-weight: 700; color: var(--color-danger); font-size: 0.95rem; letter-spacing: 0.02em;">SECURITY ALERT: {len(current_alerts)} THREAT DETECTION(S)</div>
                <div style="color: var(--text-primary); font-size: 0.84rem;">Identified {high_alerts} High-Risk and {medium_alerts} Medium-Risk alerts across {unique_ips_count} unique source IP(s).</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Build enriched alerts
    enriched_alerts = []
    for a in current_alerts:
        target_ip = a.get("ip")
        matching_logs = [l for l in current_logs if (l.get("ip") == target_ip or l.get("ip_address") == target_ip)]

        usernames = list(set(
            str(l.get("username")) for l in matching_logs
            if l.get("username") and str(l.get("username")) not in ("UNKNOWN", "None", "")
        ))
        users_str = ", ".join(usernames[:4]) if usernames else "N/A"

        timestamps = [str(l.get("timestamp")) for l in matching_logs if l.get("timestamp")]
        ts_str = timestamps[0] if timestamps else "—"

        sources = list(set(str(l.get("source") or l.get("source_type") or "Auth Log") for l in matching_logs))
        source_str = sources[0] if sources else "System Log"

        enriched_alerts.append({
            "timestamp": ts_str,
            "alert_type": a.get("alert_type", "Unknown"),
            "ip_address": target_ip or "Unknown",
            "username": users_str,
            "count": a.get("failed_attempts", 0),
            "severity": a.get("severity", "HIGH"),
            "risk_score": a.get("risk_score", 50),
            "source": source_str
        })

    # Filter controls in 4 responsive columns
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        sev_opts = ["ALL"] + sorted(set(a["severity"] for a in enriched_alerts))
        sel_sev = st.selectbox("Filter Severity", sev_opts, key=f"alt_sev_{key_suffix}")
    with f2:
        type_opts = ["ALL"] + sorted(set(a["alert_type"] for a in enriched_alerts))
        sel_type = st.selectbox("Filter Alert Type", type_opts, key=f"alt_type_{key_suffix}")
    with f3:
        search_ip = st.text_input("Search Source IP", placeholder="e.g. 192.168.1.", key=f"alt_ip_{key_suffix}")
    with f4:
        search_user = st.text_input("Search Target User", placeholder="e.g. admin", key=f"alt_user_{key_suffix}")

    filtered = enriched_alerts
    if sel_sev != "ALL":
        filtered = [a for a in filtered if a["severity"] == sel_sev]
    if sel_type != "ALL":
        filtered = [a for a in filtered if a["alert_type"] == sel_type]
    if search_ip.strip():
        filtered = [a for a in filtered if search_ip.strip().lower() in a["ip_address"].lower()]
    if search_user.strip():
        filtered = [a for a in filtered if search_user.strip().lower() in a["username"].lower()]

    c_cnt, c_mode, c_dl = st.columns([3, 3, 2])
    with c_cnt:
        st.markdown(
            f"<div style='font-size: 0.82rem; color: #94A3B8; padding-top: 8px;'>Displaying <strong style='color: #F8FAFC;'>{len(filtered)}</strong> of {len(enriched_alerts)} alerts</div>",
            unsafe_allow_html=True
        )
    with c_mode:
        view_mode = st.radio("Display View", ["🗂️ Card View", "📊 Table View"], horizontal=True, key=f"alt_view_mode_{key_suffix}")
    with c_dl:
        if filtered:
            df_export = pd.DataFrame(filtered)
            csv_data = df_export.to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export CSV",
                data=csv_data,
                file_name=f"security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key=f"dl_alerts_{key_suffix}",
                use_container_width=True
            )

    if not filtered:
        st.info("No security alerts match the selected filter criteria.")
    elif view_mode == "📊 Table View":
        df_tbl = pd.DataFrame(filtered)
        col_rename = {
            "timestamp": "First Event",
            "alert_type": "Alert Type",
            "ip_address": "Source IP",
            "username": "Target User(s)",
            "count": "Attempts",
            "severity": "Severity",
            "risk_score": "Risk Score",
            "source": "Log Source"
        }
        df_tbl = df_tbl.rename(columns=col_rename)
        st.dataframe(df_tbl, use_container_width=True, hide_index=True)
    else:
        for alert in filtered:
            sev = alert["severity"].upper()
            badge_html = severity_badge_html(sev)
            border_col = {"HIGH": "#EF4444", "MEDIUM": "#F59E0B"}.get(sev, "#3B82F6")
            risk = alert["risk_score"]
            risk_col = "#EF4444" if risk >= 70 else ("#F59E0B" if risk >= 40 else "#3B82F6")

            st.markdown(
                f"""
                <div class="alert-row" style="border-left: 4px solid {border_col};">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                        <div>
                            <div style="font-size: 0.95rem; font-weight: 700; color: #F8FAFC; display: flex; align-items: center; gap: 8px; flex-wrap: wrap;">
                                {alert['alert_type']}
                                {badge_html}
                            </div>
                            <div style="font-size: 0.74rem; color: #64748B; margin-top: 2px;">
                                Source: <span style="color: #94A3B8;">{alert['source']}</span> · First Event: <span style="color: #94A3B8;">{alert['timestamp']}</span>
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 0.68rem; color: #94A3B8; text-transform: uppercase;">Risk Score</div>
                            <div style="font-size: 1.2rem; font-weight: 800; color: {risk_col};">{risk} <span style="font-size: 0.68rem; color: #64748B;">/ 100</span></div>
                        </div>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 8px; background: rgba(11, 18, 32, 0.5); padding: 8px 12px; border-radius: 6px; font-size: 0.80rem;">
                        <div>
                            <span style="color: #64748B; font-size: 0.68rem; text-transform: uppercase;">Source IP</span><br>
                            <code style="color: #22D3EE; font-weight: 600;">{alert['ip_address']}</code>
                        </div>
                        <div>
                            <span style="color: #64748B; font-size: 0.68rem; text-transform: uppercase;">Target Username(s)</span><br>
                            <strong style="color: #E2E8F0;">{alert['username']}</strong>
                        </div>
                        <div>
                            <span style="color: #64748B; font-size: 0.68rem; text-transform: uppercase;">Event Count</span><br>
                            <strong style="color: #EF4444;">{alert['count']} attempts</strong>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    # SQLite Database history expander
    with st.expander(f"🗄️ View SQLite Database History ({db_record_count} total alerts)", expanded=False):
        db_rows = get_db_alerts()
        if not db_rows:
            st.caption("No alerts currently stored in security_alerts.db. Run analysis on security logs containing attacks to store alerts.")
        else:
            df_db = pd.DataFrame(
                db_rows,
                columns=["Alert ID", "Rule / Alert Type", "Source IP", "Failed Attempts", "Severity", "Risk Score"]
            )
            dh1, dh2 = st.columns(2)
            with dh1:
                db_sev_opts = ["ALL"] + sorted(df_db["Severity"].dropna().unique().tolist())
                sel_db_sev = st.selectbox("Filter DB by Severity", db_sev_opts, key=f"db_sev_filter_{key_suffix}")
            with dh2:
                search_db_ip = st.text_input("Search DB Source IP", placeholder="e.g. 192.168.1.", key=f"db_ip_filter_{key_suffix}")

            filtered_db = df_db.copy()
            if sel_db_sev != "ALL":
                filtered_db = filtered_db[filtered_db["Severity"] == sel_db_sev]
            if search_db_ip.strip():
                filtered_db = filtered_db[filtered_db["Source IP"].astype(str).str.contains(search_db_ip.strip(), case=False, na=False)]

            dh_cnt, dh_btn = st.columns([3, 1])
            with dh_cnt:
                st.caption(f"Showing {len(filtered_db)} of {len(df_db)} database records")
            with dh_btn:
                csv_db = filtered_db.to_csv(index=False).encode("utf-8")
                st.download_button(
                    "📥 Export DB (CSV)",
                    data=csv_db,
                    file_name=f"db_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    key=f"db_export_btn_{key_suffix}",
                    use_container_width=True
                )

            st.dataframe(filtered_db, use_container_width=True, hide_index=True)


def render_analytics_timeline_gauge_section(current_logs, current_alerts, total_events, successful_logins, failed_logins):
    """Renders Section 5 (Timeline) and Section 6 (Threat-Risk Gauge)."""
    col_t1, col_t2 = st.columns([7, 5])
    with col_t1:
        st.markdown(
            """
            <div class="chart-header">
                <span class="chart-title">📈 05. Authentication Activity Timeline</span>
                <span class="chart-badge">AREA SPLINE</span>
            </div>
            <div class="chart-desc">Sequential authentication trends over time comparing success vs failure volume.</div>
            """,
            unsafe_allow_html=True
        )
        fig_time = build_auth_timeline_figure(current_logs, height=310)
        if fig_time:
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("Timestamps could not be extracted for timeline visualization. Upload security logs to populate.")

    with col_t2:
        st.markdown(
            """
            <div class="chart-header">
                <span class="chart-title">🛡️ 06. SOC Threat-Risk Gauge</span>
                <span class="chart-badge chart-badge-danger">INDEX</span>
            </div>
            <div class="chart-desc">Automated threat severity index calculated from active alert triggers.</div>
            """,
            unsafe_allow_html=True
        )
        fig_gauge = build_threat_risk_gauge_figure(current_alerts, successful_logins, failed_logins, total_events, height=310)
        if fig_gauge:
            st.plotly_chart(fig_gauge, use_container_width=True)
        else:
            st.markdown("<div style='color: #64748B; padding: 40px 0; text-align: center;'>No threat posture data available.</div>", unsafe_allow_html=True)


def render_analytics_donuts_section(current_alerts, total_events, successful_logins, failed_logins):
    """Renders Section 7 (Severity Donut) and Section 8 (Authentication Outcome Donut)."""
    col_m1, col_m2 = st.columns(2)
    with col_m1:
        st.markdown(
            """
            <div class="chart-header">
                <span class="chart-title">🎯 07. Alert Severity Distribution</span>
                <span class="chart-badge">DONUT</span>
            </div>
            <div class="chart-desc">Proportion of triggered alerts categorised into High, Medium, or Low severity.</div>
            """,
            unsafe_allow_html=True
        )
        fig_sev = build_severity_donut_figure(current_alerts, total_events, successful_logins, failed_logins, height=300)
        if fig_sev:
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("No security alerts recorded. Clean environment.")

    with col_m2:
        st.markdown(
            """
            <div class="chart-header">
                <span class="chart-title">⚖️ 08. Successful vs Failed Authentication</span>
                <span class="chart-badge">DONUT</span>
            </div>
            <div class="chart-desc">Ratio of authorized access sessions versus rejected authentication attempts.</div>
            """,
            unsafe_allow_html=True
        )
        fig_auth = build_auth_outcome_donut_figure(successful_logins, failed_logins, height=300)
        if fig_auth:
            st.plotly_chart(fig_auth, use_container_width=True)
        else:
            st.info("No authentication events available.")


def render_analytics_bars_section(current_logs, current_alerts):
    """Renders Section 9: Top Suspicious IP Addresses & Targeted Accounts."""
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        st.markdown(
            """
            <div class="chart-header">
                <span class="chart-title">🚨 09. Top Suspicious Source IPs</span>
                <span class="chart-badge chart-badge-danger">RANKING BAR</span>
            </div>
            <div class="chart-desc">Hostile source addresses ranked by total unauthorized authentication volume.</div>
            """,
            unsafe_allow_html=True
        )
        fig_ips = build_suspicious_ips_bar_figure(current_logs, current_alerts, height=290)
        if fig_ips:
            st.plotly_chart(fig_ips, use_container_width=True)
        else:
            st.markdown("<div style='padding: 30px 10px; text-align: center; color: #64748B; font-size: 0.82rem;'>No failed login IPs found.</div>", unsafe_allow_html=True)

    with col_b2:
        st.markdown(
            """
            <div class="chart-header">
                <span class="chart-title">👤 Top Targeted User Accounts</span>
                <span class="chart-badge">GROUPED BAR</span>
            </div>
            <div class="chart-desc">Identifies user accounts subjected to repeated authorization attempts.</div>
            """,
            unsafe_allow_html=True
        )
        fig_users = build_targeted_users_bar_figure(current_logs, height=290)
        if fig_users:
            st.plotly_chart(fig_users, use_container_width=True)
        else:
            st.markdown("<div style='padding: 30px 10px; text-align: center; color: #64748B; font-size: 0.82rem;'>No user account data.</div>", unsafe_allow_html=True)

    # Optional rule trigger frequency
    if current_alerts:
        with st.expander("📊 Detection Rule Trigger Frequency", expanded=False):
            fig_rules = build_attack_types_bar_figure(current_alerts, height=240)
            if fig_rules:
                st.plotly_chart(fig_rules, use_container_width=True)


def render_parsed_events_table_section(current_logs, total_events, key_suffix="main"):
    """Renders Section 10: Parsed Events Table with search, status filtering, and CSV export."""
    if not current_logs:
        render_empty_state(
            "📋",
            "No Parsed Events Available",
            "Upload security log files above to parse and inspect normalized authentication records."
        )
        return

    df_events = pd.DataFrame(current_logs)
    ec1, ec2, ec3 = st.columns([2, 3, 3])
    with ec1:
        evt_status = st.selectbox("Status Filter", ["ALL", "FAILED", "SUCCESS"], key=f"pe_stat_{key_suffix}")
    with ec2:
        evt_user = st.text_input("Search Username", placeholder="e.g. administrator", key=f"pe_user_{key_suffix}")
    with ec3:
        evt_ip = st.text_input("Search IP Address", placeholder="e.g. 192.168.1.", key=f"pe_ip_{key_suffix}")

    df_filtered = df_events.copy()
    if evt_status != "ALL":
        df_filtered = df_filtered[df_filtered["status"] == evt_status]
    if evt_user.strip():
        df_filtered = df_filtered[df_filtered["username"].astype(str).str.contains(evt_user.strip(), case=False, na=False)]
    if evt_ip.strip():
        ip_col = "ip" if "ip" in df_filtered.columns else "ip_address"
        df_filtered = df_filtered[df_filtered[ip_col].astype(str).str.contains(evt_ip.strip(), case=False, na=False)]

    display_cols = []
    for col in ["timestamp", "event", "username", "ip_address", "status", "source", "event_id", "source_port", "logon_type"]:
        if col in df_filtered.columns:
            display_cols.append(col)

    c_info, c_btn = st.columns([3, 1])
    with c_info:
        st.markdown(f"<div style='font-size: 0.82rem; color: #94A3B8; padding-top: 8px;'>Displaying <strong style='color: #F8FAFC;'>{len(df_filtered):,}</strong> of {len(df_events):,} parsed events</div>", unsafe_allow_html=True)
    with c_btn:
        if not df_filtered.empty:
            exp_cols = display_cols if display_cols else df_filtered.columns.tolist()
            csv_events = df_filtered[exp_cols].to_csv(index=False).encode("utf-8")
            st.download_button(
                "📥 Export Events (CSV)",
                data=csv_events,
                file_name=f"parsed_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key=f"dl_events_{key_suffix}",
                use_container_width=True
            )

    if display_cols:
        df_display = df_filtered[display_cols].copy().fillna("—")
        st.dataframe(df_display, use_container_width=True, hide_index=True, height=min(450, 35 * len(df_display) + 38))
    else:
        st.dataframe(df_filtered, use_container_width=True, hide_index=True)


def generate_incident_report_text(current_logs, current_alerts, total_events, failed_logins, successful_logins, high_alerts, medium_alerts, unique_ips_count, files_analyzed):
    """Generate professional ASCII / Markdown Incident Analysis report."""
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    files_str = ", ".join(st.session_state.analyzed_files) if st.session_state.analyzed_files else "N/A"

    report = f"""================================================================================
SECURITY OPERATIONS CENTER (SOC) - INCIDENT ANALYSIS REPORT
================================================================================
Generated: {now_str}
Project:   Security Log Analyzer v2.0
Analyzed:  {files_str} ({files_analyzed} file(s))

1. EXECUTIVE SUMMARY
--------------------------------------------------------------------------------
Total Authentication Events: {total_events}
Successful Authorizations:  {successful_logins}
Failed Authentications:     {failed_logins}
Security Alerts Triggered:  {len(current_alerts)}
High-Severity Threats:      {high_alerts}
Medium-Severity Threats:    {medium_alerts}
Unique Hostile Source IPs:  {unique_ips_count}
Security Posture Status:    {'ELEVATED / CRITICAL' if len(current_alerts) > 0 else 'SECURE / NORMAL'}

2. DETECTED THREAT INCIDENTS
--------------------------------------------------------------------------------
"""
    if not current_alerts:
        report += "No threats detected. All events represent legitimate authentication activity.\n"
    else:
        for i, a in enumerate(current_alerts, 1):
            report += f"[{i}] {a.get('alert_type', 'Unknown Alert')}\n"
            report += f"    Source IP:        {a.get('ip', 'N/A')}\n"
            report += f"    Failed Attempts:  {a.get('failed_attempts', 0)}\n"
            report += f"    Severity / Score: {a.get('severity', 'HIGH')} ({a.get('risk_score', 0)}/100)\n"
            report += f"    Recommended Action: Block IP on perimeter firewall, audit target accounts.\n\n"

    report += """3. RECOMMENDED REMEDIATION ACTIONS
--------------------------------------------------------------------------------
1. Apply perimeter firewall / iptables drop rules against identified hostile IP addresses.
2. Enable account lockout policies after 3 failed login attempts.
3. Enforce Multi-Factor Authentication (MFA) across all remote access services.
4. Export and archive normalized audit events for compliance and digital forensics.
================================================================================
"""
    return report


def render_export_reports_section(current_logs, current_alerts, total_events, failed_logins, successful_logins, high_alerts, medium_alerts, unique_ips_count, files_analyzed, key_suffix="main"):
    """Renders Section 11: Export Reports & Data."""
    if not st.session_state.analysis_done or not current_logs:
        st.info("No analyzed data available. Upload security logs above to generate incident reports and export data.")
        return

    exp1, exp2, exp3 = st.columns(3)
    with exp1:
        st.markdown(
            """
            <div class="soc-panel" style="padding: 14px 16px; margin-bottom: 10px;">
                <div style="font-size: 1.1rem; margin-bottom: 4px;">🚨</div>
                <div style="font-weight: 700; color: #F8FAFC; font-size: 0.88rem;">Security Alerts CSV</div>
                <div style="color: #94A3B8; font-size: 0.74rem; margin-bottom: 10px;">Threat records with IPs, severities and risk scores.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        if current_alerts:
            df_alert_exp = pd.DataFrame(current_alerts)
            csv_alerts = df_alert_exp.to_csv(index=False).encode("utf-8")
            st.download_button(
                "Download Alerts CSV",
                data=csv_alerts,
                file_name=f"security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                key=f"rep_alerts_{key_suffix}",
                use_container_width=True
            )
        else:
            st.caption("Clean analysis (0 alerts to export).")

    with exp2:
        st.markdown(
            """
            <div class="soc-panel" style="padding: 14px 16px; margin-bottom: 10px;">
                <div style="font-size: 1.1rem; margin-bottom: 4px;">📋</div>
                <div style="font-weight: 700; color: #F8FAFC; font-size: 0.88rem;">Parsed Events CSV</div>
                <div style="color: #94A3B8; font-size: 0.74rem; margin-bottom: 10px;">All normalized authentication event records.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        df_logs_exp = pd.DataFrame(current_logs)
        csv_logs = df_logs_exp.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download Events CSV",
            data=csv_logs,
            file_name=f"parsed_events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            key=f"rep_events_{key_suffix}",
            use_container_width=True
        )

    with exp3:
        st.markdown(
            """
            <div class="soc-panel" style="padding: 14px 16px; margin-bottom: 10px;">
                <div style="font-size: 1.1rem; margin-bottom: 4px;">📊</div>
                <div style="font-weight: 700; color: #F8FAFC; font-size: 0.88rem;">Analysis Summary JSON</div>
                <div style="color: #94A3B8; font-size: 0.74rem; margin-bottom: 10px;">Structured JSON summary with metrics and threat data.</div>
            </div>
            """,
            unsafe_allow_html=True
        )
        summary_dict = {
            "generated_at": datetime.now().isoformat(),
            "analysis_time": st.session_state.last_analysis_time,
            "files_analyzed": st.session_state.analyzed_files,
            "file_count": files_analyzed,
            "metrics": {
                "total_events": total_events,
                "failed_logins": failed_logins,
                "successful_logins": successful_logins,
                "total_alerts": len(current_alerts),
                "high_risk_alerts": high_alerts,
                "medium_risk_alerts": medium_alerts,
                "unique_source_ips": unique_ips_count
            },
            "alerts": current_alerts
        }
        json_bytes = json.dumps(summary_dict, indent=2).encode("utf-8")
        st.download_button(
            "Download Summary JSON",
            data=json_bytes,
            file_name=f"analysis_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            key=f"rep_json_{key_suffix}",
            use_container_width=True
        )

    # Incident Report text generator
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    report_text = generate_incident_report_text(
        current_logs, current_alerts, total_events, failed_logins,
        successful_logins, high_alerts, medium_alerts, unique_ips_count, files_analyzed
    )
    with st.expander("📄 View Generated SOC Incident Report (Markdown / Text)", expanded=False):
        st.code(report_text, language="markdown")
        st.download_button(
            "📥 Download Formal Incident Report (.txt)",
            data=report_text.encode("utf-8"),
            file_name=f"SOC_Incident_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            key=f"rep_txt_{key_suffix}",
            use_container_width=True
        )


def render_detection_rules_section():
    """Renders Detection Rules and System Workflow Pipeline."""
    st.markdown(
        """
        <div class="soc-panel-title">🔄 END-TO-END SYSTEM WORKFLOW PIPELINE</div>
        <div class="wf-step-container">
            <div class="wf-step-card">
                <div class="wf-step-num">STAGE 01</div>
                <div class="wf-step-title">Log Ingestion & Detection</div>
                <div class="wf-step-desc">Accepts multi-file uploads (.csv, .log, .txt). Inspects file headers to identify Windows CSV, Event Viewer Text, SSH Syslog, or Pipe-delimited logs.</div>
            </div>
            <div class="wf-step-card">
                <div class="wf-step-num">STAGE 02</div>
                <div class="wf-step-title">Extraction & Normalization</div>
                <div class="wf-step-desc">Extracts timestamp, event type, username, IP (IPv4/IPv6), port, and status. Normalizes records into a unified Python dictionary schema.</div>
            </div>
            <div class="wf-step-card">
                <div class="wf-step-num">STAGE 03</div>
                <div class="wf-step-title">Detection Rule Engine</div>
                <div class="wf-step-desc">Evaluates normalized events against rule criteria: Brute-Force (≥3 failed from IP) and Multiple-Account spray (≥3 distinct failed usernames from IP).</div>
            </div>
            <div class="wf-step-card">
                <div class="wf-step-num">STAGE 04</div>
                <div class="wf-step-title">Severity & Risk Scoring</div>
                <div class="wf-step-desc">Assigns severity classifications (HIGH / MEDIUM / LOW) and calibrated risk scores (70/100 for brute-force, 50/100 for account spraying).</div>
            </div>
            <div class="wf-step-card">
                <div class="wf-step-num">STAGE 05</div>
                <div class="wf-step-title">Persistent SQLite Storage</div>
                <div class="wf-step-desc">Stores newly generated alerts in security_alerts.db table, executing deduplication checks to prevent duplicate alerts from re-analysis.</div>
            </div>
            <div class="wf-step-card">
                <div class="wf-step-num">STAGE 06</div>
                <div class="wf-step-title">SOC Analytics & Reporting</div>
                <div class="wf-step-desc">Renders interactive timelines, severity donuts, top IP charts, searchable alert tables, and generates CSV/JSON audit exports.</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    rcol1, rcol2 = st.columns(2)
    with rcol1:
        st.markdown(
            """
            <div class="rule-card" style="border-left: 4px solid #EF4444; height: 100%;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                    <div>
                        <span style="font-size: 0.7rem; color: #22D3EE; font-family: 'JetBrains Mono', monospace; font-weight: 700;">SEC-RUL-001</span>
                        <div style="font-size: 1rem; font-weight: 700; color: #F8FAFC; margin-top: 2px;">Brute-Force Authentication Attack</div>
                    </div>
                    <span class="sev-badge sev-high">HIGH</span>
                </div>
                <p style="font-size: 0.80rem; color: #CBD5E1; line-height: 1.5; margin-bottom: 10px;">
                    Fires when authentication failure count from a single source IP reaches or exceeds the configured threshold (default: ≥5 attempts).
                </p>
                <div style="background: rgba(11, 18, 32, 0.6); padding: 8px 12px; border-radius: 6px; font-size: 0.74rem;">
                    <div style="color: #94A3B8;">MITRE ATT&CK: <strong style="color: #EF4444;">T1110 (Brute Force)</strong></div>
                    <div style="color: #94A3B8;">Calibrated Risk Score: <strong style="color: #EF4444;">70 / 100</strong></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    with rcol2:
        st.markdown(
            """
            <div class="rule-card" style="border-left: 4px solid #F59E0B; height: 100%;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                    <div>
                        <span style="font-size: 0.7rem; color: #22D3EE; font-family: 'JetBrains Mono', monospace; font-weight: 700;">SEC-RUL-002</span>
                        <div style="font-size: 1rem; font-weight: 700; color: #F8FAFC; margin-top: 2px;">Multiple-Account Credential Spraying</div>
                    </div>
                    <span class="sev-badge sev-medium">MEDIUM</span>
                </div>
                <p style="font-size: 0.80rem; color: #CBD5E1; line-height: 1.5; margin-bottom: 10px;">
                    Fires when authentication failures from a single source IP target multiple distinct usernames (default: ≥3 accounts).
                </p>
                <div style="background: rgba(11, 18, 32, 0.6); padding: 8px 12px; border-radius: 6px; font-size: 0.74rem;">
                    <div style="color: #94A3B8;">MITRE ATT&CK: <strong style="color: #F59E0B;">T1110.003 (Password Spraying)</strong></div>
                    <div style="color: #94A3B8;">Calibrated Risk Score: <strong style="color: #F59E0B;">50 / 100</strong></div>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


def render_project_info_section():
    """Renders Section 12: Project Information, Architecture, Limitations, and Future Scope."""
    st.markdown(
        """
        <div class="info-box">
            <h3>A. Problem Statement</h3>
            <p>
                Security logs generated by operating systems and network services contain critical information about authentication activity.
                However, manually inspecting large volumes of log data is time-consuming and error-prone. Suspicious patterns such as brute-force attacks or credential spraying can easily be missed.
            </p>
            <p>
                This Security Log Analyzer automatically parses heterogeneous log sources, normalizes events into a consistent structure, applies rule-based threat detection logic, and presents real actionable intelligence.
            </p>
        </div>
        <div class="info-box">
            <h3>B. Supported Log Formats</h3>
            <ul>
                <li><strong>Windows Security CSV:</strong> Exported CSV files with <code>EventID</code> (4624/4625), <code>SourceIP</code>, <code>LogonType</code>.</li>
                <li><strong>Windows Event Viewer Text:</strong> Text logs containing <code>TimeCreated</code>, <code>Id: 4624/4625</code>, <code>Account Name</code>, and <code>Source Network Address</code>.</li>
                <li><strong>Linux / Kali SSH Syslog:</strong> Syslog format containing <code>sshd</code> authentication messages (Failed/Accepted password, Invalid user, IPv4 & IPv6).</li>
                <li><strong>Pipe-Delimited Standard Auth:</strong> Standard format: <code>timestamp | event | username | ip | status</code>.</li>
            </ul>
        </div>
        <div class="info-box">
            <h3>C. Limitations & Scope</h3>
            <ul>
                <li>The system analyzes <strong>uploaded log files</strong> — it does not perform continuous kernel-level packet capture.</li>
                <li>Detection rules use frequency and identity thresholds; advanced time-window sliding analysis is planned for future releases.</li>
                <li>IP geolocation and external threat intelligence APIs require active internet connectivity and are not bundled in offline demonstrations.</li>
            </ul>
        </div>
        <div class="info-box">
            <h3>D. Project & Academic Credentials</h3>
            <p>
                <strong>Security Log Analyzer & SOC Monitoring Dashboard</strong><br>
                College Project &middot; BCA Cybersecurity v2.0<br>
                Stack: Python, Streamlit, Pandas, Plotly, SQLite, Regex Normalization.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# HELPER: SECTION HEADING WITH SMOOTH SCROLL ANCHOR
# ============================================================

def render_section_heading(anchor_id: str, title_text: str, desc_text: str = None):
    """Renders a responsive section heading with an HTML anchor for scroll navigation."""
    desc_html = f'<div class="soc-section-desc">{desc_text}</div>' if desc_text else ''
    st.markdown(
        f'<div id="{anchor_id}" class="soc-section-heading"><span>{title_text}</span></div>'
        + desc_html,
        unsafe_allow_html=True
    )


# ============================================================
# SIDEBAR NAVIGATION & CONTROLS (COMPACT LAPTOP FIT)
# ============================================================

with st.sidebar:
    st.markdown(
        """
        <div style="padding: 6px 0 10px 0; display: flex; align-items: center; gap: 10px;">
            <div style="font-size: 1.6rem;">🛡️</div>
            <div>
                <div style="font-weight: 800; font-size: 0.98rem; letter-spacing: 0.04em; color: #F8FAFC;">
                    SECURITY LOG ANALYZER
                </div>
                <div style="font-size: 0.7rem; color: #22D3EE; font-weight: 600; letter-spacing: 0.06em;">
                    SOC MONITORING &bull; LAPTOP SUITE
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Dual Navigation Mode
    nav_mode = st.radio(
        "Navigation Mode",
        [
            "📜 Full Dashboard (Scroll View)",
            "📑 Focused View (Single Page)"
        ],
        index=0,
        help="Scroll View renders all SOC sections on a single vertically scrollable page. Focused View lets you inspect individual sections."
    )

    if nav_mode == "📜 Full Dashboard (Scroll View)":
        st.markdown(
            """
            <div style="font-size: 0.68rem; font-weight: 700; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.06em; margin: 8px 0 4px 0;">
                QUICK SECTION JUMP
            </div>
            <div class="soc-jump-grid">
                <a href="#sec-overview" class="soc-jump-btn">📊 Overview</a>
                <a href="#sec-kpis" class="soc-jump-btn">🔢 KPIs</a>
                <a href="#sec-upload" class="soc-jump-btn">📂 Ingestion</a>
                <a href="#sec-alerts" class="soc-jump-btn">🚨 Alerts</a>
                <a href="#sec-timeline" class="soc-jump-btn">📈 Timeline</a>
                <a href="#sec-gauge" class="soc-jump-btn">🛡️ Risk Gauge</a>
                <a href="#sec-severity" class="soc-jump-btn">🎯 Severity</a>
                <a href="#sec-suspicious-ips" class="soc-jump-btn">🚨 Hostile IPs</a>
                <a href="#sec-events" class="soc-jump-btn">📋 Events</a>
                <a href="#sec-reports" class="soc-jump-btn">📑 Reports</a>
                <a href="#sec-rules" class="soc-jump-btn">⚙️ Rules & Info</a>
            </div>
            """,
            unsafe_allow_html=True
        )
    else:
        focused_page = st.radio(
            "Select Section",
            [
                "📊 Overview Dashboard",
                "📂 Log Analysis",
                "🚨 Security Alerts",
                "🛡️ Detection Rules",
                "📑 Reports & Export",
                "ℹ️ Project Information"
            ],
            index=0
        )

    st.markdown("<hr style='margin: 10px 0; border-color: rgba(56, 189, 248, 0.12);'>", unsafe_allow_html=True)

    # ── Detection & Workflow Settings ──
    with st.expander("⚙️ Detection Parameters", expanded=False):
        bf_val = st.number_input(
            "Brute-Force Threshold",
            min_value=1,
            max_value=20,
            value=st.session_state.get("bf_threshold", 5),
            help="Failed login attempts from a single IP required to trigger SEC-RUL-001 (Default: 5)."
        )
        st.session_state["bf_threshold"] = int(bf_val)

        ma_val = st.number_input(
            "Multiple-Account Threshold",
            min_value=2,
            max_value=15,
            value=st.session_state.get("ma_threshold", 3),
            help="Distinct usernames targeted with failed logins from a single IP to trigger SEC-RUL-002 (Default: 3)."
        )
        st.session_state["ma_threshold"] = int(ma_val)

        mode_choice = st.radio(
            "Analysis Pacing Mode",
            ["⏱️ Demo Mode (10–12s Pacing)", "⚡ Normal Mode (Immediate)"],
            index=0 if st.session_state.get("demo_mode", True) else 1,
            help="Demo mode paces the 7 workflow stages for presentations. Normal mode finishes immediately as processing completes."
        )
        st.session_state["demo_mode"] = ("Demo" in mode_choice)

    # ── Theme Customizer ──
    with st.expander("🎨 Dashboard Theme", expanded=False):
        theme_names = list(THEME_PALETTES.keys())
        current_idx = 0
        if "app_theme_choice" in st.session_state and st.session_state["app_theme_choice"] in theme_names:
            current_idx = theme_names.index(st.session_state["app_theme_choice"])
        st.selectbox(
            "Color Scheme",
            options=theme_names,
            index=current_idx,
            key="app_theme_choice",
            help="Curated cybersecurity color palettes."
        )

    # System status panel
    db_connected, db_record_count = get_database_status()
    st.markdown(
        f"""
        <div style="background: rgba(14, 23, 38, 0.9); border: 1px solid var(--border-default); border-radius: 8px; padding: 10px 12px; margin: 10px 0;">
            <div style="font-size: 0.68rem; font-weight: 700; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px;">
                SYSTEM STATUS
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 4px;">
                <span style="color: #CBD5E1;">SOC Engine</span>
                <span style="color: #4ADE80; font-weight: 600;">● Online</span>
            </div>
            <div style="display: flex; justify-content: space-between; font-size: 0.78rem; margin-bottom: 4px;">
                <span style="color: #CBD5E1;">SQLite DB</span>
                <span style="color: {'#38BDF8' if db_connected else '#EF4444'}; font-weight: 600;">
                    {'● Connected' if db_connected else '● Offline'}
                </span>
            </div>
            <div style="font-size: 0.68rem; color: #64748B; margin-top: 4px;">
                Archived alerts: <strong style="color: #94A3B8;">{db_record_count}</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Supported Formats
    st.markdown(
        """
        <div style="font-size: 0.68rem; font-weight: 700; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 4px;">
            SUPPORTED FORMATS
        </div>
        <div style="font-size: 0.74rem; color: #CBD5E1; line-height: 1.6; margin-bottom: 10px;">
            &bull; Windows Security CSV<br>
            &bull; Windows Event Viewer Log<br>
            &bull; Linux / Kali SSH Syslog<br>
            &bull; Pipe-delimited Auth Log
        </div>
        """,
        unsafe_allow_html=True
    )

    # Quick-load sample buttons
    st.markdown(
        "<div style='font-size: 0.68rem; font-weight: 700; color: #94A3B8; text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 6px;'>DEMO SAMPLE CONTROLS</div>",
        unsafe_allow_html=True
    )
    qcol1, qcol2 = st.columns(2)
    with qcol1:
        if st.button("🚨 Attack", help="Load Windows Attack Sample CSV", use_container_width=True):
            sample_path = os.path.join(PROJECT_ROOT, "data", "logs", "windows_attack_sample.csv")
            if os.path.exists(sample_path):
                st.session_state["trigger_quick_load"] = ("windows_attack_sample.csv", sample_path)
                st.rerun()

    with qcol2:
        if st.button("📄 Clean", help="Load 200 Windows Event 4624 logs", use_container_width=True):
            clean_path = os.path.join(PROJECT_ROOT, "data", "logs", "windows_security_compact.csv")
            if os.path.exists(clean_path):
                st.session_state["trigger_quick_load"] = ("windows_security_compact.csv", clean_path)
                st.rerun()

    if st.button("🔄 Reset View", help="Clear current session analysis. Database records are preserved.", use_container_width=True):
        st.session_state.logs = []
        st.session_state.alerts = []
        st.session_state.analyzed_files = []
        st.session_state.analyzed_file_details = []
        st.session_state.analysis_done = False
        st.session_state.last_analysis_time = None
        st.session_state.analysis_metrics = None
        st.session_state.analysis_duration = 0.0
        st.session_state.unrecognized_lines = 0
        st.rerun()

    st.markdown("<hr style='margin: 10px 0; border-color: rgba(56, 189, 248, 0.12);'>", unsafe_allow_html=True)
    st.caption("🛡️ Security Log Analyzer &bull; College Project v2.0")


# ============================================================
# HANDLE QUICK LOAD DEMO TRIGGERED FROM SIDEBAR
# ============================================================

if st.session_state.get("trigger_quick_load"):
    ql_name, ql_path = st.session_state.pop("trigger_quick_load")
    if os.path.exists(ql_path):
        main_prog_box = st.empty()
        wrapper = LocalFileWrapper(ql_name, ql_path)
        is_demo = st.session_state.get("demo_mode", True)
        min_dur = 10.0 if is_demo else 0.2
        bf_thresh = st.session_state.get("bf_threshold", 5)
        ma_thresh = st.session_state.get("ma_threshold", 3)
        execute_analysis_workflow(
            [wrapper], main_prog_box,
            min_visible_duration=min_dur,
            demo_mode=is_demo,
            bf_threshold=bf_thresh,
            ma_threshold=ma_thresh
        )
        st.rerun()


# ============================================================
# COMPUTED METRICS (REAL DATA ONLY)
# ============================================================

current_logs = st.session_state.logs
current_alerts = st.session_state.alerts

total_events = len(current_logs)
failed_logins = sum(1 for log in current_logs if log.get("status") == "FAILED")
successful_logins = sum(1 for log in current_logs if log.get("status") == "SUCCESS")
total_alerts = len(current_alerts)

high_alerts = sum(1 for a in current_alerts if a.get("severity") == "HIGH")
medium_alerts = sum(1 for a in current_alerts if a.get("severity") == "MEDIUM")
low_alerts = sum(1 for a in current_alerts if a.get("severity") == "LOW")

all_ips = set()
for log in current_logs:
    ip = log.get("ip") or log.get("ip_address")
    if ip and str(ip) not in ("-", "", "None", "UNKNOWN"):
        all_ips.add(ip)
unique_ips_count = len(all_ips)

files_analyzed = len(st.session_state.analyzed_file_details)
unrec_lines = st.session_state.get("unrecognized_lines", 0)
if (total_events + unrec_lines) > 0:
    parsing_rate = (total_events / (total_events + unrec_lines)) * 100.0
else:
    parsing_rate = 100.0 if total_events > 0 else 0.0

db_connected, db_record_count = get_database_status()


# ============================================================
# MAIN ROUTING: SCROLLABLE DASHBOARD VS FOCUSED VIEW
# ============================================================

if nav_mode == "📜 Full Dashboard (Scroll View)":

    # ── Section 01: Header and Project Status ──
    render_header_banner(db_connected, db_record_count)

    # ── Section 02: KPI Summary Cards ──
    render_section_heading("sec-kpis", "02. KEY PERFORMANCE INDICATORS", "Aggregated real-time metrics across all parsed security events.")
    render_kpi_cards_section(
        total_events, failed_logins, successful_logins, total_alerts,
        high_alerts, unique_ips_count, files_analyzed, parsing_rate
    )

    # ── Section 03: Upload and Analyze Logs ──
    render_section_heading("sec-upload", "03. LOG INGESTION & REAL-TIME ANALYSIS", "Upload security log files to parse events and evaluate threat detection rules.")
    render_upload_section(key_suffix="scroll_ingest")
    if st.session_state.analysis_done:
        render_analysis_results_summary()

    # ── Section 04: Latest Security Alerts ──
    render_section_heading("sec-alerts", "04. LATEST SECURITY ALERTS", "Detected brute-force attacks and credential spraying incidents with risk scores.")
    render_latest_alerts_section(
        current_alerts, current_logs, total_events, high_alerts,
        medium_alerts, unique_ips_count, db_record_count, key_suffix="scroll_alerts"
    )

    # ── Section 05 & 06: Timeline & Threat-Risk Gauge ──
    col_t1, col_t2 = st.columns([7, 5])
    with col_t1:
        render_section_heading("sec-timeline", "05. AUTHENTICATION TIMELINE", "Time series progression of authorized vs failed logins.")
        fig_time = build_auth_timeline_figure(current_logs, height=310)
        if fig_time:
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("Timestamps could not be extracted for timeline visualization. Upload logs to populate.")

    with col_t2:
        render_section_heading("sec-gauge", "06. THREAT-RISK GAUGE", "Calibrated SOC threat posture risk score.")
        fig_gauge = build_threat_risk_gauge_figure(current_alerts, successful_logins, failed_logins, total_events, height=310)
        if fig_gauge:
            st.plotly_chart(fig_gauge, use_container_width=True)
        else:
            st.markdown("<div style='color: #64748B; padding: 30px 0; text-align: center;'>No threat posture data available.</div>", unsafe_allow_html=True)

    # ── Section 07 & 08: Severity Donut & Auth Outcome Donut ──
    col_m1, col_m2 = st.columns(2)
    with col_m1:
        render_section_heading("sec-severity", "07. ALERT SEVERITY DISTRIBUTION", "Proportion of triggered alerts by severity level.")
        fig_sev = build_severity_donut_figure(current_alerts, total_events, successful_logins, failed_logins, height=300)
        if fig_sev:
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("No security alerts recorded. Clean environment.")

    with col_m2:
        render_section_heading("sec-auth-ratio", "08. SUCCESSFUL VS FAILED AUTHENTICATION", "Ratio of authorized logins vs failed attempts.")
        fig_auth = build_auth_outcome_donut_figure(successful_logins, failed_logins, height=300)
        if fig_auth:
            st.plotly_chart(fig_auth, use_container_width=True)
        else:
            st.info("No authentication events available.")

    # ── Section 09: Top Suspicious IP Addresses & Targeted Accounts ──
    col_b1, col_b2 = st.columns(2)
    with col_b1:
        render_section_heading("sec-suspicious-ips", "09. TOP SUSPICIOUS IP ADDRESSES", "Hostile source addresses ranked by unauthorized attempt volume.")
        fig_ips = build_suspicious_ips_bar_figure(current_logs, current_alerts, height=290)
        if fig_ips:
            st.plotly_chart(fig_ips, use_container_width=True)
        else:
            st.markdown("<div style='padding: 30px 10px; text-align: center; color: #64748B; font-size: 0.82rem;'>No failed login IPs found.</div>", unsafe_allow_html=True)

    with col_b2:
        render_section_heading("sec-targeted-users", "TARGETED USER ACCOUNTS", "Identifies user accounts subjected to repeated authentication attempts.")
        fig_users = build_targeted_users_bar_figure(current_logs, height=290)
        if fig_users:
            st.plotly_chart(fig_users, use_container_width=True)
        else:
            st.markdown("<div style='padding: 30px 10px; text-align: center; color: #64748B; font-size: 0.82rem;'>No user account data.</div>", unsafe_allow_html=True)

    # ── Section 10: Parsed Events Table ──
    render_section_heading("sec-events", "10. PARSED EVENTS TABLE", "Normalized security events with search, filtering, and export.")
    render_parsed_events_table_section(current_logs, total_events, key_suffix="scroll_pe")

    # ── Section 11: Export Reports ──
    render_section_heading("sec-reports", "11. EXPORT REPORTS & AUDIT DATA", "Generate formal incident reports and download CSV/JSON data.")
    render_export_reports_section(
        current_logs, current_alerts, total_events, failed_logins,
        successful_logins, high_alerts, medium_alerts, unique_ips_count,
        files_analyzed, key_suffix="scroll_rep"
    )

    # ── Section 12: Project Information and Limitations ──
    render_section_heading("sec-rules", "12. DETECTION RULES & PROJECT SPECIFICATIONS", "Detection engine rules, pipeline workflow, and academic project specifications.")
    render_detection_rules_section()
    render_project_info_section()

else:
    # ── FOCUSED VIEW (SINGLE PAGE MODE) ──
    render_header_banner(db_connected, db_record_count)
    render_kpi_cards_section(
        total_events, failed_logins, successful_logins, total_alerts,
        high_alerts, unique_ips_count, files_analyzed, parsing_rate
    )

    if focused_page == "📊 Overview Dashboard":
        if not st.session_state.analysis_done:
            render_empty_state("🛡️", "No Security Events Analyzed Yet", "Upload security log files below to begin analysis, or click <b>🚨 Attack</b> / <b>📄 Clean</b> in the sidebar.")
            render_upload_section(key_suffix="focused_ov_init")
        else:
            with st.expander("📂 Upload / Analyze Additional Logs", expanded=False):
                render_upload_section(key_suffix="focused_ov_more")
            render_analysis_results_summary()
            render_latest_alerts_section(
                current_alerts, current_logs, total_events, high_alerts,
                medium_alerts, unique_ips_count, db_record_count, key_suffix="focused_ov_alerts"
            )
            render_analytics_timeline_gauge_section(current_logs, current_alerts, total_events, successful_logins, failed_logins)
            render_analytics_donuts_section(current_alerts, total_events, successful_logins, failed_logins)
            render_analytics_bars_section(current_logs, current_alerts)

    elif focused_page == "📂 Log Analysis":
        render_upload_section(key_suffix="focused_la_upload")
        if st.session_state.analysis_done:
            render_analysis_results_summary()
            render_parsed_events_table_section(current_logs, total_events, key_suffix="focused_la_pe")

    elif focused_page == "🚨 Security Alerts":
        render_latest_alerts_section(
            current_alerts, current_logs, total_events, high_alerts,
            medium_alerts, unique_ips_count, db_record_count, key_suffix="focused_alerts"
        )

    elif focused_page == "🛡️ Detection Rules":
        render_detection_rules_section()

    elif focused_page == "📑 Reports & Export":
        render_export_reports_section(
            current_logs, current_alerts, total_events, failed_logins,
            successful_logins, high_alerts, medium_alerts, unique_ips_count,
            files_analyzed, key_suffix="focused_reports"
        )

    elif focused_page == "ℹ️ Project Information":
        render_project_info_section()


# ============================================================
# FOOTER
# ============================================================

st.markdown(
    """
    <div class="soc-footer">
        <div>🛡️ Security Log Analyzer &middot; SOC Monitoring Dashboard</div>
        <div>College Project &middot; BCA Cybersecurity v2.0</div>
    </div>
    """,
    unsafe_allow_html=True
)