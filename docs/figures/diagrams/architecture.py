"""Figure 4.1 - layered architecture diagram (drawn directly, so the layout stays clean)."""
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

out = Path(sys.argv[1]).resolve() / "ch4_fig1_architecture"
INK, INK2, EDGE = "#0b0b0b", "#52514e", "#898781"
FILL, BAND, ACCENT, STORE = "#ffffff", "#f4f3ef", "#2a78d6", "#e8f0fb"
plt.rcParams.update({"font.family": ["Segoe UI", "DejaVu Sans"], "font.size": 10})

fig, ax = plt.subplots(figsize=(16, 11))
ax.set_xlim(0, 16)
ax.set_ylim(0, 11)
ax.axis("off")


def band(x, y, w, h, title):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=0.15",
                                fc=BAND, ec="#d6d4cc", lw=1))
    ax.text(x + 0.15, y + h - 0.12, title, ha="left", va="top", fontsize=10.5, fontweight="semibold", color=INK2, zorder=5, bbox=dict(fc=BAND, ec="none", pad=1.5))


def box(cx, cy, text, w=2.1, h=0.75, fc=FILL, ec=EDGE, bold=False):
    ax.add_patch(FancyBboxPatch((cx - w / 2, cy - h / 2), w, h, boxstyle="round,pad=0,rounding_size=0.08",
                                fc=fc, ec=ec, lw=1.2))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=9.5, color=INK, linespacing=1.25,
            fontweight="semibold" if bold else "normal")


def arrow(x1, y1, x2, y2, label="", both=False, dashed=False, lx=None, ly=None, ha="left"):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="<|-|>" if both else "-|>", color=INK2, lw=1.4,
                                linestyle=(0, (4, 3)) if dashed else "-", shrinkA=2, shrinkB=2, mutation_scale=14))
    if label:
        ax.text(lx if lx is not None else (x1 + x2) / 2 + 0.1, ly if ly is not None else (y1 + y2) / 2, label,
                ha=ha, va="center", fontsize=9, color=INK2, style="italic",
                bbox=dict(fc="white", ec="none", pad=1.5))


# Layer 1: users and external systems
band(0.2, 9.4, 15.6, 1.45, "Users and external systems")
box(1.6, 9.95, "Log sources\nWindows, Sysmon, Zeek, Proxy,\nCloudTrail, DHCP, Metrics", w=2.7, h=0.95)
box(5.0, 9.95, "Threat hunter", fc="#fff7ef", ec="#eb6834")
box(7.6, 9.95, "Analyst / CISO", fc="#fff7ef", ec="#eb6834")
box(10.6, 9.95, "External TI feeds\nThreatFox, MISP, TAXII, OTX ...", w=2.6, h=0.9)
box(14.3, 9.95, "LLM provider (optional)\nGroq / OpenAI-compatible", w=2.6, h=0.9)

# Layer 2: interfaces
band(0.2, 7.85, 15.6, 1.2, "Interfaces (FastAPI)")
box(3.0, 8.3, "Command API  :8000", w=2.5, bold=True)
box(6.3, 8.3, "Web dashboard  :8080", w=2.5, bold=True)
box(13.85, 8.3, "Query API  :8001", w=2.5, bold=True)

# Layer 3: command side workers
band(0.2, 4.15, 11.2, 3.3, "Command side: single-writer workers (commands queued in PostgreSQL)")
workers = [["Normaliser\nECS + entity resolution", "Summary engine\ndrop / aggregate policy", "Indexer\nBloom + BM25 (Tantivy)",
            "Feature extractor\nversioned, summaries only", "Seal manager\nmanifest + sealed tag"],
           ["Rule service\ncompiler, planner, executor", "Cost estimator\n+ calibration", "Retention enforcer\n15-year floor, drill",
            "TI enricher\npseudonymise + validate", "Feed connectors\nSDK, auto-discovered"]]
for r, row in enumerate(workers):
    for c, t in enumerate(row):
        box(1.35 + c * 2.2, 6.55 - r * 1.15, t, w=2.05, h=0.85)
box(5.75, 4.5, "Orchestrator (reconciler): submits missing work as commands", w=10.6, h=0.42, fc="#fbfaf7")

# Query side column
band(11.7, 0.2, 4.1, 7.25, "Messaging and query side")
box(12.85, 2.75, "PostgreSQL\ncommands + outbox", w=1.95, h=0.8, fc=STORE, ec=ACCENT)
box(12.85, 4.0, "Redis Streams\nevent bus", w=1.95, h=0.8, fc=STORE, ec=ACCENT)
box(12.85, 5.25, "Projectors", w=1.95, h=0.6)
box(12.85, 6.45, "Read models\nPostgreSQL", w=1.95, h=0.8, fc=STORE, ec=ACCENT)
box(14.85, 6.45, "DuckDB\nsnapshot-pinned", w=1.6, h=0.8)

# Storage layer
band(0.2, 0.2, 11.2, 3.55, "Object storage (MinIO, S3-compatible)  +  Iceberg tables via Lakekeeper REST catalog")
stores = [("raw/\nParquet, WORM", 1.35), ("summary/\nIceberg", 3.55), ("artefacts/\nIceberg", 5.75),
          ("index/ (hot)\nbloom + BM25", 7.95), ("results/\nIceberg", 10.15)]
for t, x in stores:
    box(x, 2.55, t, w=2.0, h=0.85, fc=STORE, ec=ACCENT)
box(1.35, 0.95, "archive tier\n(deep archive)", w=2.0, h=0.8, fc=STORE, ec=ACCENT)
box(5.75, 0.95, "ti/  tactical / operational / strategic (Iceberg)", w=6.4, h=0.7, fc=STORE, ec=ACCENT)

# Flows
arrow(5.0, 9.5, 6.0, 8.68)
arrow(7.6, 9.5, 6.7, 8.68)
arrow(5.05, 8.3, 4.27, 8.3)
arrow(7.57, 8.45, 12.58, 8.45)
arrow(3.0, 7.92, 3.0, 7.45, "commands", lx=3.1, ly=7.66)
arrow(1.45, 9.47, 1.35, 7.0, "raw logs", lx=1.5, ly=7.66)
arrow(10.6, 9.5, 10.6, 7.45, "feed pulls (to feed connectors)", lx=10.45, ly=7.66, ha="right")
arrow(14.3, 9.5, 11.3, 7.45, "pseudonymised bundles (TI enricher)", both=True, lx=12.75, ly=9.2, ha="left")
arrow(5.75, 4.28, 5.75, 3.0, "writes", lx=5.85, ly=3.95)
arrow(11.4, 4.3, 11.88, 2.85, "events (outbox)", lx=11.2, ly=3.95, ha="right")
arrow(12.85, 3.15, 12.85, 3.6)
arrow(12.85, 4.4, 12.85, 4.95)
arrow(12.85, 5.55, 12.85, 6.05)
arrow(13.6, 7.92, 13.1, 6.87)
arrow(14.2, 7.92, 14.75, 6.87)
ax.plot([14.85, 14.85], [6.05, 1.2], color=INK2, lw=1.4)
arrow(14.85, 1.2, 11.42, 1.2, "snapshot-pinned reads", lx=13.1, ly=1.45, ha="center")
arrow(1.35, 2.12, 1.35, 1.35, "sealed=true only", dashed=True, lx=1.45, ly=1.73)

for ext in ("png", "svg"):
    fig.savefig(out.with_suffix(f".{ext}"), dpi=300, bbox_inches="tight", facecolor="white")
print("wrote", out)
