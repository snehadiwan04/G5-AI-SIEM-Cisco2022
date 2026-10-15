"""
G5 - AI-Powered SIEM for Detecting Credential Theft and Lateral Movement
Case study: Cisco data breach (2022)

One-command entry point: runs the detection experiment, then draws the figures.

    python main.py            # full run: 20 seeds per scenario (about 2 minutes)
    python main.py --quick    # demo run: 3 seeds per scenario (about 20 seconds)
    python main.py --out myresults

This file is also the entry point for the standalone executable (see build_exe_windows.bat).
"""
import argparse
import os
import runpy
import sys
import time

# Imported here so that PyInstaller bundles them into the executable.
import numpy  # noqa: F401
import pandas  # noqa: F401
import sklearn.ensemble  # noqa: F401
import sklearn.metrics  # noqa: F401
import matplotlib  # noqa: F401
matplotlib.use("Agg")
import matplotlib.pyplot  # noqa: F401,E402


def script_dir():
    # When frozen by PyInstaller, bundled files live in sys._MEIPASS.
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def run_script(name, args):
    path = os.path.join(script_dir(), name)
    saved = sys.argv
    sys.argv = [path] + args
    try:
        runpy.run_path(path, run_name="__main__")
    finally:
        sys.argv = saved


def main():
    p = argparse.ArgumentParser(description="G5 AI-SIEM prototype (Cisco 2022 case study)")
    p.add_argument("--quick", action="store_true", help="3 seeds per scenario instead of 20")
    p.add_argument("--seeds", type=int, default=None, help="number of random seeds per scenario")
    p.add_argument("--out", default="results", help="output folder (default: results)")
    a = p.parse_args()
    seeds = a.seeds or (3 if a.quick else 20)
    os.makedirs(a.out, exist_ok=True)

    print("=" * 70)
    print(" G5 AI-SIEM prototype: credential theft and lateral movement detection")
    print(f" Scenarios: Cisco replica + stealth variant | seeds per scenario: {seeds}")
    print(f" Output folder: {os.path.abspath(a.out)}")
    print("=" * 70)
    t0 = time.time()
    print("\n[1/2] Simulating the enterprise, injecting the attack, running detectors ...\n")
    run_script("siem_prototype.py", [a.out, str(seeds)])
    print("\n[2/2] Drawing figures ...")
    run_script("make_figures.py", [a.out])
    print(f"\nDone in {time.time() - t0:.0f} s. Open the '{a.out}' folder to see summary.csv and the fig*.png files.")


if __name__ == "__main__":
    main()
    if getattr(sys, "frozen", False):
        input("\nPress Enter to close this window ...")
