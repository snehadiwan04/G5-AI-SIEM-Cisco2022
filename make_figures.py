"""Draws the six report figures from the outputs of siem_prototype.py.
Run: python make_figures.py [outdir]   (default: results)
"""
import pickle, sys, warnings
warnings.filterwarnings("ignore")
import numpy as np, pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from sklearn.metrics import roc_curve, roc_auc_score

O = sys.argv[1] if len(sys.argv) > 1 else "results"
plt.rcParams.update({"font.family": "serif", "font.serif": ["Times New Roman", "Liberation Serif", "DejaVu Serif"], "font.size": 10,
                     "axes.edgecolor": "black", "axes.labelcolor": "black", "xtick.color": "black", "ytick.color": "black"})
NAVY, BLUE, MID, LIGHT, PALE = "#0b2a5b", "#1f4e9c", "#4a7fd0", "#9dbbe8", "#dfe9f8"

def box(ax, x, y, w, h, txt, fc=PALE, ec=NAVY, fs=8.5, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=1.2))
    ax.text(x + w / 2, y + h / 2, txt, ha="center", va="center", fontsize=fs, color="black",
            fontweight="bold" if bold else "normal", wrap=True)

def arrow(ax, x1, y1, x2, y2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="-|>", color=NAVY, lw=1.2))

# ---------- Fig 1: Cisco 2022 kill chain (vertical)
fig, ax = plt.subplots(figsize=(7.0, 5.6)); ax.set_xlim(0, 10); ax.set_ylim(0, 8.0); ax.axis("off")
stages = [
    ("1. Credential theft", "Employee's corporate password synced from Chrome to a personal Google account that the attacker controlled", "T1078 Valid Accounts"),
    ("2. MFA bypass", "Repeated vishing calls + MFA push fatigue until one push was approved; attacker enrolled new MFA devices", "T1621, T1098.005"),
    ("3. VPN access", "Authenticated to Cisco VPN as the victim from attacker devices; Tor and residential IP space", "T1078, T1090.003"),
    ("4. Lateral movement", "Logons to many systems, pivot through Citrix servers to domain controllers via RDP/Citrix", "T1021 Remote Services"),
    ("5. Credential dumping", "ntdsutil IFM copy of NTDS, reg save of SAM/SYSTEM/SECURITY, LSASS MiniDump via comsvcs.dll", "T1003.001 / .002 / .003"),
    ("6. Persistence & evasion", "Local admin 'z' created then deleted, IFEO sethc/narrator debugger keys, wevtutil cl, LogMeIn/TeamViewer", "T1136.001, T1546.012, T1070.001, T1219"),
    ("7. Exfiltration & extortion", "NTDS sent over SMB to attacker VPN host; Box folder taken; file list leaked, contents posted 11 Sep 2022", "T1048"),
]
for i, (t, dsc, m) in enumerate(stages):
    y = 7.0 - i * 1.0
    box(ax, 0.05, y, 2.3, 0.78, t, fc=BLUE, fs=8.2, bold=True); ax.texts[-1].set_color("white")
    box(ax, 2.55, y, 5.25, 0.78, "\n".join(__import__("textwrap").wrap(dsc, 56)), fs=7.3)
    ax.text(7.95, y + 0.39, "\n".join(__import__("textwrap").wrap(m, 22)), va="center", fontsize=7.4, color=NAVY, style="italic")
    if i < 6:
        arrow(ax, 1.2, y, 1.2, y - 0.22)
ax.text(2.55, 7.88, "Observed behaviour (Talos, Aug 2022)", fontsize=8, fontweight="bold")
ax.text(7.95, 7.88, "MITRE ATT&CK", fontsize=8, fontweight="bold")
fig.savefig(f"{O}/fig1_killchain.png", dpi=220, bbox_inches="tight"); plt.close(fig)

# ---------- Fig 2: architecture
fig, ax = plt.subplots(figsize=(7.2, 4.4)); ax.set_xlim(0, 10); ax.set_ylim(0, 7); ax.axis("off")
srcs = ["IdP / MFA logs\n(push, deny, enrol)", "VPN gateway\n(geo, ASN, device)", "Windows Security\n4624/4625/4768/4769", "Sysmon / EDR\n(process cmd-line)", "Citrix, SMB,\nfirewall logs"]
for i, s in enumerate(srcs):
    box(ax, 0.05, 5.9 - i * 1.25, 1.75, 0.95, s, fs=7.4)
    arrow(ax, 1.8, 6.37 - i * 1.25, 2.3, 3.6)
box(ax, 2.3, 2.6, 1.6, 2.0, "Ingestion &\nnormalisation\n(ECS schema,\nentity resolution,\ntime alignment)", fs=7.6)
dets = [("Detector A\nSignature rules\n(Sigma-style)", 5.3), ("Detector B\nUEBA - Isolation\nForest (10 features)", 3.45), ("Detector C\nGraph link prediction\n(auth graph, paths)", 1.6)]
for t, y in dets:
    box(ax, 4.5, y, 1.9, 1.15, t, fc=PALE, fs=7.5)
    arrow(ax, 3.9, 3.6, 4.5, y + 0.57)
    arrow(ax, 6.4, y + 0.57, 6.9, 3.6)
box(ax, 6.9, 2.5, 1.45, 2.2, "Correlation &\nrisk scoring\n(entity x 24 h,\nATT&CK tactic\ndiversity bonus)", fc=LIGHT, fs=7.5)
box(ax, 8.65, 4.2, 1.3, 1.1, "Analyst alert\n+ evidence\nnarrative", fc=BLUE, fs=7.5); ax.texts[-1].set_color("white")
box(ax, 8.65, 2.55, 1.3, 1.1, "SOAR action:\nrevoke tokens,\ndisable device", fc=BLUE, fs=7.2); ax.texts[-1].set_color("white")
box(ax, 8.65, 0.9, 1.3, 1.1, "Analyst\nfeedback ->\nretrain/tune", fs=7.4)
arrow(ax, 8.35, 3.9, 8.65, 4.75); arrow(ax, 8.35, 3.4, 8.65, 3.1); arrow(ax, 9.3, 2.55, 9.3, 2.0)
ax.annotate("", xy=(5.45, 1.6), xytext=(8.65, 1.2), arrowprops=dict(arrowstyle="-|>", color=MID, lw=1, ls="--", connectionstyle="arc3,rad=0.25"))
fig.savefig(f"{O}/fig2_architecture.png", dpi=220, bbox_inches="tight"); plt.close(fig)

# ---------- Fig 3: risk score per entity-day (seed 0, Cisco replica)
d = pickle.load(open(f"{O}/run0_full.pkl", "rb"))
r = d["risk"].copy(); r["lab"] = r.entity + " / d" + r.day.astype(str)
top = r.sort_values("score", ascending=False).head(12).iloc[::-1]
fig, ax = plt.subplots(figsize=(6.4, 3.6))
mal = {(d["victim"], 24), (d["victim"], 25), ("dc0$", 25), (d["victim"], 26)}
cols = [NAVY if (e, dd) in mal else LIGHT for e, dd in zip(top.entity, top.day)]
ax.barh(top.lab, top.score, color=cols, edgecolor="black", lw=0.5)
ax.axvline(100, color="black", ls="--", lw=1); ax.text(108, 0.2, "alert threshold = 100", fontsize=8)
ax.set_xscale("log"); ax.set_xlabel("Correlated entity risk score (log scale)")
ax.set_title("Top-12 entity-days by risk (dark = attacker activity)", fontsize=10)
fig.savefig(f"{O}/fig3_risk.png", dpi=220, bbox_inches="tight"); plt.close(fig)

# ---------- Fig 4: ROC
fig, ax = plt.subplots(figsize=(4.6, 4.0))
styles = {"UEBA (no range guard)": ("black", ":"), "UEBA (Isolation Forest)": (BLUE, "-"), "Graph (single edge)": (MID, "--"), "Graph link prediction": (NAVY, "-.")}
names = {"UEBA (no range guard)": "UEBA, IF without range guard", "Graph link prediction": "Graph, path-aggregated", "Graph (single edge)": "Graph, single edge", "UEBA (Isolation Forest)": "UEBA, Isolation Forest"}
for k, (y, s) in d["roc"].items():
    f, t, _ = roc_curve(y, s); c, ls = styles[k]
    ax.plot(f, t, color=c, ls=ls, lw=1.6, label=f"{names[k]} (AUC={roc_auc_score(y, s):.3f})")
ax.plot([0, 1], [0, 1], color="black", lw=0.6, ls=":")
ax.set_xscale("symlog", linthresh=0.01); ax.set_xlim(0, 1); ax.set_ylim(0, 1.02)
ax.set_xlabel("False positive rate (symlog)"); ax.set_ylabel("True positive rate"); ax.legend(fontsize=7.5, loc="lower right")
ax.set_title("ROC of learned detectors (seed 0)", fontsize=10)
fig.savefig(f"{O}/fig4_roc.png", dpi=220, bbox_inches="tight"); plt.close(fig)

# ---------- Fig 5: method comparison
R = pd.read_csv(f"{O}/per_seed.csv")
order = ["Signature rules", "UEBA (Isolation Forest)", "Graph link prediction", "Fused AI-SIEM (correlated)"]
short = ["Rules", "UEBA", "Graph", "Fused"]
fig, axs = plt.subplots(1, 3, figsize=(7.4, 2.9))
for ax, metric, ttl in zip(axs, ["recall", "precision", "alerts_per_day"], ["Recall (entity-day)", "Precision", "Alerts per day"]):
    for j, (scen, col) in enumerate([("Cisco-replica", NAVY), ("Stealth variant", LIGHT)]):
        g = R[R.scenario == scen].groupby("method")[metric].agg(["mean", "std"]).reindex(order)
        ax.bar(np.arange(4) + (j - 0.5) * 0.38, g["mean"], 0.38, yerr=g["std"], color=col, edgecolor="black", lw=0.5,
               capsize=2, label=scen, error_kw=dict(lw=0.7))
    ax.set_xticks(range(4)); ax.set_xticklabels(short, fontsize=8); ax.set_title(ttl, fontsize=9)
axs[0].legend(fontsize=7, loc="upper left")
fig.tight_layout(); fig.savefig(f"{O}/fig5_compare.png", dpi=220, bbox_inches="tight"); plt.close(fig)

# ---------- Fig 6: stage coverage heatmaps
fig, axs = plt.subplots(1, 2, figsize=(7.2, 3.3), sharey=True)
for ax, tag, ttl in zip(axs, ["full", "stealth"], ["Cisco-replica", "Stealth variant"]):
    dd = pickle.load(open(f"{O}/run0_{tag}.pkl", "rb"))["stage_cov"]
    st = ["Initial Access", "Credential Access", "Persistence", "Discovery", "Lateral Movement",
          "Privilege Escalation", "Defense Evasion", "Command and Control", "Exfiltration"]
    M = np.array([[dd.get(s, {}).get(k, 0) / max(dd.get(s, {}).get("n", 1), 1) for k in ["rule", "ueba", "graph"]] for s in st])
    ax.imshow(M, cmap="Blues", vmin=0, vmax=1, aspect="auto")
    for i in range(M.shape[0]):
        for j in range(3):
            ax.text(j, i, f"{M[i, j]*100:.0f}%", ha="center", va="center", fontsize=7.5, color="white" if M[i, j] > 0.6 else "black")
    ax.set_xticks(range(3)); ax.set_xticklabels(["Rules", "UEBA", "Graph"]); ax.set_title(ttl, fontsize=9)
    ax.set_yticks(range(len(st))); ax.set_yticklabels(st, fontsize=8)
fig.suptitle("Share of attack events per ATT&CK tactic covered by each detector", fontsize=9.5)
fig.tight_layout(); fig.savefig(f"{O}/fig6_coverage.png", dpi=220, bbox_inches="tight"); plt.close(fig)
print("ok")
