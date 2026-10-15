# AI-Powered SIEM for Detecting Credential Theft and Lateral Movement
### A Case Study of the Cisco Data Breach (2022) — Group 5

**Course:** Cyber Security, CA-II Case Study (Experiential Learning) · Dept. of E&TC, SIT Pune
**Faculty:** Dr Mangal Singh
**GitHub:** https://github.com/snehadiwan04/G5-AI-SIEM-Cisco2022

---

## 1. What this project does

In May 2022 an attacker entered Cisco's network using a stolen password and MFA push fatigue, then moved laterally to the domain controllers using only valid accounts and built-in Windows tools (Cisco Talos, Aug 2022). This project tests whether an AI-assisted SIEM could have detected that attack earlier than signature rules alone.

The prototype:

1. **Simulates an enterprise** — 300 users, 351 hosts, 30 days of MFA, VPN, Windows logon and process logs (about 56,000 events per run), with realistic benign noise.
2. **Injects the Cisco 2022 attack chain** as labelled events, using the command lines published by Talos, in two scenarios:
   - **Cisco replica** — faithful copy of the reported attack.
   - **Stealth variant** — no MFA burst, office hours, every tool renamed or obfuscated.
3. **Runs three detectors:**
   - **A. Signature rules** — 9 Sigma-style command-line rules + an MFA-burst rule.
   - **B. UEBA** — Isolation Forest on 10 behavioural features per user-hour, with a range guard.
   - **C. Graph link prediction** — user→host authentication graph; scores logins to never-used hosts, summed into paths.
4. **Fuses them** in a risk-correlation layer: `R = Σ points × (1 + 0.5·(K − 1))`, alert when `R ≥ 100` (K = number of detectors that agree on the same account and day).
5. **Evaluates** recall, precision, false-positive rate, alerts per day, time to detect and ROC AUC over 20 random seeds per scenario, and draws the report's figures.

## 2. Folder structure

```
G5_AI_SIEM_Cisco2022/
├── README.md                 ← this file
├── requirements.txt          ← Python packages
├── run_windows.bat           ← one-click run (Windows)
├── run_mac_linux.sh          ← one-command run (macOS / Linux)
├── build_exe_windows.bat     ← builds a standalone G5_AI_SIEM.exe
├── src/
│   ├── main.py               ← entry point: runs the experiment, then the figures
│   ├── siem_prototype.py     ← data generation, attack injection, 3 detectors, fusion, evaluation
│   └── make_figures.py       ← draws Fig. 1–6 used in the report
└── results/                  ← outputs from the full 20-seed run (same numbers as the report)
```

## 3. Requirements

- **Python 3.9 or newer** ([python.org/downloads](https://www.python.org/downloads/)). On Windows, tick **"Add Python to PATH"** during install.
- Packages (installed automatically by the run scripts): `numpy`, `pandas`, `scikit-learn`, `matplotlib`.
- No GPU, no internet access during the run, no external datasets. Any laptop works.

## 4. How to run

### Option A — one click (recommended)

| System | What to do |
|---|---|
| Windows | Double-click **`run_windows.bat`** |
| macOS / Linux | In a terminal, inside this folder: `./run_mac_linux.sh` |

### Option B — manual commands

```bash
pip install -r requirements.txt
python src/main.py              # full run, 20 seeds per scenario (~1–2 minutes)
python src/main.py --quick      # demo run, 3 seeds per scenario (~15 seconds)
python src/main.py --seeds 10 --out myresults
```

The two stages can also be run separately:

```bash
python src/siem_prototype.py results 20     # experiment → CSVs
python src/make_figures.py results          # figures from those CSVs
```

### Option C — standalone executable (Windows)

Run **`build_exe_windows.bat`** once on a Windows PC with Python installed. It uses PyInstaller to create `dist\G5_AI_SIEM.exe`. Double-click the exe; results appear in a `results` folder next to it. The exe is not included in this zip because it is about 100 MB on its own.

## 5. Output

Everything is written to the `results/` folder:

| File | Contents |
|---|---|
| `summary.csv` | Mean and std of every metric, per scenario and detector (Table 5 in the report) |
| `per_seed.csv` | Raw metrics for each of the 20 seeds |
| `attack_events_full.csv`, `attack_events_stealth.csv` | The injected attack events with ATT&CK stage labels |
| `fig1_killchain.png` | Cisco 2022 attack chain mapped to MITRE ATT&CK |
| `fig2_architecture.png` | Pipeline architecture |
| `fig3_risk.png` | Top-12 risk scores: attacker vs normal users |
| `fig4_roc.png` | ROC curves of the learned detectors |
| `fig5_compare.png` | Recall, precision and alert load per detector |
| `fig6_coverage.png` | Detector coverage per ATT&CK tactic |
| `run0_*.pkl` | Intermediate data for seed 0, used by the figure script |

## 6. Expected results (full run, mean of 20 seeds)

| Scenario | Detector | Recall | Precision | Alerts / day | Time to detect |
|---|---|---|---|---|---|
| Cisco replica | Signature rules | 0.50 | 1.00 | 0.22 | 0 h |
| | Isolation Forest (UEBA) | 0.83 | 0.06 | 5.95 | 0 h |
| | Graph link prediction | 0.71 | 0.66 | 0.52 | 2.1 h |
| | **Fused pipeline** | **0.75** | **1.00** | **0.33** | **0 h** |
| Stealth variant | Signature rules | 0.25 | 1.00 | 0.11 | 17 h |
| | **Fused pipeline** | **0.75** | **1.00** | **0.33** | **2 h** |

Results are deterministic: the same seeds give the same numbers on any machine (small differences are possible across library versions). The `--quick` run uses only 3 seeds, so its averages differ slightly.

## 7. How the code maps to the report

| Report section | Code |
|---|---|
| 3.2 Threat model, 4.3 Attack injection | `gen_attack()` in `siem_prototype.py` |
| 3.3 Telemetry, 4.2 Synthetic enterprise | `build_env()`, `gen_benign()` |
| 3.4 Detector A: signature rules | `SIG`, `rule_engine()`, `mfa_burst_rule()` |
| 3.5 Detector B: Isolation Forest | `ueba_features()`, range guard inside `run()` |
| 3.6 Detector C: graph link prediction | `graph_scores()`, path aggregation inside `run()` |
| 3.7 Correlation and risk scoring | evidence points and `risk` table inside `run()` |
| 3.8 Evaluation protocol | `ed_eval()`, time-to-detect and ROC inside `run()` |
| Figures 1–6 | `make_figures.py` |

## 8. Limitations

The data is synthetic, so the fused pipeline's perfect precision is an upper bound, not a production estimate. The attack is compressed into three days, the detectors are deliberately simple baselines, and no detector catches the final SMB exfiltration. See Section 5.8 of the report.

## 9. Primary source

N. Biasini, "Cisco Talos shares insights related to recent cyber attack on Cisco," Cisco Talos Intelligence Blog, 10 Aug 2022. https://blog.talosintelligence.com/recent-cyber-attack/
