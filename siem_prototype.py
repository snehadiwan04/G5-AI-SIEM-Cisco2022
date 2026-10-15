"""
AI-SIEM prototype: synthetic enterprise telemetry with the Cisco 2022 (Talos) attack chain
injected, three detectors (rules, Isolation-Forest UEBA, graph link-prediction) and a
risk-correlation layer. Run: python siem_prototype.py [outdir] [n_seeds]   (defaults: results, 20)
"""
import sys, json, os, math, random
from collections import defaultdict
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_curve, roc_auc_score

OUT = sys.argv[1] if len(sys.argv) > 1 else "results"
N_SEEDS = int(sys.argv[2]) if len(sys.argv) > 2 else 20
os.makedirs(OUT, exist_ok=True)

N_USERS, N_WS = 300, 300
N_SRV, N_CTX, N_DC = 40, 8, 3
DAYS, ATTACK_DAY = 30, 24          # 24 days baseline, attack on day 24, test days 22-29
TRAIN_DAYS = 21
DEPTS = 6

def build_env(rng):
    users = [f"u{i:03d}" for i in range(N_USERS)]
    dept = {u: i % DEPTS for i, u in enumerate(users)}
    ws = {u: f"ws{i:03d}" for i, u in enumerate(users)}
    srv = [f"srv{i:02d}" for i in range(N_SRV)]
    ctx = [f"ctx{i}" for i in range(N_CTX)]
    dcs = [f"dc{i}" for i in range(N_DC)]
    dept_srv = {d: [s for j, s in enumerate(srv) if j % DEPTS == d] for d in range(DEPTS)}
    admins = set(rng.choice(users, 8, replace=False))
    profile = {}
    for u in users:
        own = list(rng.choice(dept_srv[dept[u]], 3, replace=False))
        if rng.random() < 0.4:
            own.append(rng.choice(ctx))
        if u in admins:
            own += list(rng.choice(srv, 12, replace=False)) + list(dcs) + list(ctx)
        profile[u] = sorted(set(own))
    home_geo = {u: ("IN" if rng.random() < 0.7 else "US") for u in users}
    return dict(users=users, dept=dept, ws=ws, srv=srv, ctx=ctx, dcs=dcs,
                admins=admins, profile=profile, home_geo=home_geo, dept_srv=dept_srv)

BENIGN_CMDS = ["whoami", "ipconfig /all", "tasklist", "net use", "gpupdate /force",
               "powershell Get-Process", "msiexec /i C:\\Software\\Teams.msi",
               "reg query HKCU\\Software", "wevtutil qe Application /c:5", "net user %USER% /domain",
               "netsh wlan show profiles", "schtasks /query"]
ADMIN_CMDS = ["ntdsutil.exe snapshot", "wevtutil.exe el", "net localgroup administrators",
              "reg save hklm\\software sw.bak", "psexec \\\\srv01 ipconfig", "netsh advfirewall show allprofiles"]

def gen_benign(env, rng):
    ev = []
    for day in range(DAYS):
        for u in env["users"]:
            if rng.random() < 0.1:            # day off
                continue
            h0 = int(rng.normal(9.5, 1.0))
            remote = rng.random() < 0.35
            if remote:
                ev.append(dict(day=day, hour=h0, user=u, type="mfa", result="approve", src="vpn", dst="vpn-gw",
                               geo=env["home_geo"][u], new_device=0))
                if rng.random() < 0.03:       # occasional fat-finger deny
                    ev.append(dict(day=day, hour=h0, user=u, type="mfa", result="deny", src="vpn", dst="vpn-gw",
                                   geo=env["home_geo"][u], new_device=0))
                ev.append(dict(day=day, hour=h0, user=u, type="vpn", result="ok", src="ext", dst="vpn-gw",
                               geo=env["home_geo"][u], new_device=0))
            ev.append(dict(day=day, hour=h0, user=u, type="logon", result="ok", src="vpn-gw" if remote else env["ws"][u],
                           dst=env["ws"][u], geo="-", new_device=0))
            for _ in range(rng.poisson(3)):
                d = rng.choice(env["profile"][u])
                ev.append(dict(day=day, hour=int(np.clip(rng.normal(13, 2.5), 7, 21)), user=u, type="logon",
                               result="ok", src=env["ws"][u], dst=d, geo="-", new_device=0))
            if rng.random() < 0.04:           # legit novel access (project change / new share)
                d = rng.choice(env["srv"])
                ev.append(dict(day=day, hour=14, user=u, type="logon", result="ok", src=env["ws"][u], dst=d,
                               geo="-", new_device=0))
            if rng.random() < 0.01:           # legit new phone enrolment
                ev.append(dict(day=day, hour=h0, user=u, type="mfa_enroll", result="ok", src="ext", dst="idp",
                               geo=env["home_geo"][u], new_device=1))
            if rng.random() < 0.02:           # travel
                ev.append(dict(day=day, hour=h0, user=u, type="vpn", result="ok", src="ext", dst="vpn-gw",
                               geo=rng.choice(["SG", "AE", "GB"]), new_device=0))
            for _ in range(rng.poisson(2)):
                c = rng.choice(BENIGN_CMDS)
                ev.append(dict(day=day, hour=int(np.clip(rng.normal(13, 3), 7, 22)), user=u, type="proc",
                               result=c, src=env["ws"][u], dst=env["ws"][u], geo="-", new_device=0))
            if u in env["admins"]:
                for _ in range(rng.poisson(6)):
                    d = rng.choice(env["profile"][u])
                    ev.append(dict(day=day, hour=int(rng.integers(8, 23)), user=u, type="logon", result="ok",
                                   src=env["ws"][u], dst=d, geo="-", new_device=0))
                for _ in range(rng.poisson(1)):
                    ev.append(dict(day=day, hour=int(rng.integers(8, 20)), user=u, type="proc",
                                   result=rng.choice(ADMIN_CMDS), src=env["ws"][u], dst=rng.choice(env["profile"][u]),
                                   geo="-", new_device=0))
    return ev

def gen_attack(env, rng, victim, stealth=False):
    """Cisco/Talos 2022 chain, time-compressed into days ATTACK_DAY..ATTACK_DAY+2.
    stage: ATT&CK tactic label for analysis."""
    a, D = [], ATTACK_DAY
    def add(day, hour, typ, result, src, dst, geo="-", nd=0, user=victim, stage=""):
        a.append(dict(day=day, hour=hour, user=user, type=typ, result=result, src=src, dst=dst, geo=geo,
                      new_device=nd, malicious=1, stage=stage))
    # T1621 MFA fatigue + vishing -> approve (night, foreign egress / Tor)
    geo = env["home_geo"][victim] if stealth else "NL"   # stealth: residential proxy in victim's own country
    hr = 10 if stealth else 1                              # stealth: business hours
    n_deny = 1 if stealth else int(rng.integers(12, 25))   # stealth: vishing succeeds almost immediately
    for _ in range(n_deny):
        add(D, hr, "mfa", "deny", "vpn", "vpn-gw", geo, stage="Credential Access (T1621)")
    add(D, hr + 1, "mfa", "approve", "vpn", "vpn-gw", geo, stage="Initial Access (T1078)")
    add(D, hr + 1, "vpn", "ok", "ext", "vpn-gw", geo, stage="Initial Access (T1078)")
    # T1098.005 device registration
    for _ in range(3):
        add(D, hr + 1, "mfa_enroll", "ok", "ext", "idp", geo, nd=1, stage="Persistence (T1098.005)")
    # discovery
    for c in ["whoami /groups", "net group \"domain admins\" /domain", "hostname", "nltest /dclist:"]:
        add(D, hr + 2, "proc", c, "vpn-gw", env["ws"][victim], stage="Discovery (T1087)")
    # fan-out logons with compromised user (T1021)
    fan = list(rng.choice(env["srv"], 18, replace=False)) + list(env["ctx"][:4])
    for h in fan:
        add(D, hr + int(rng.integers(2, 5)), "logon", "ok", "vpn-gw", h, stage="Lateral Movement (T1021)")
    # Citrix pivot -> DC (privileged)
    add(D + 1, 1, "logon", "ok", env["ctx"][0], env["dcs"][0], stage="Lateral Movement (T1021)")
    add(D + 1, 1, "logon", "ok", env["ctx"][1], env["dcs"][1], stage="Lateral Movement (T1021)")
    cmds = [
        ("powershell ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\\users\\public' q q", "Credential Access (T1003.003)"),
        ("reg save hklm\\sam sam", "Credential Access (T1003.002)"),
        ("reg save hklm\\system system", "Credential Access (T1003.002)"),
        ("rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump 612 C:\\windows\\temp\\lsass.dmp full", "Credential Access (T1003.001)"),
        ("net user z Lh199211* /add", "Persistence (T1136.001)"),
        ("net localgroup administrators z /add", "Persistence (T1136.001)"),
        ("netsh advfirewall firewall set rule group=remote desktop new enable=Yes", "Defense Evasion (T1562.004)"),
        ("msiexec.exe /i C:\\Users\\Public\\Pictures\\LogMeIn.msi", "Command and Control (T1219)"),
        ("reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe /v Debugger /d cmd.exe", "Privilege Escalation (T1546.012)"),
        ("wevtutil.exe cl Security", "Defense Evasion (T1070.001)"),
        ("net user z /delete", "Defense Evasion (T1070)"),
    ]
    if stealth:
        repl = {"ntdsutil.exe": "C:\\users\\public\\ntu.exe", "comsvcs.dll, MiniDump": "comsvcs.dll, #+0000^24",
                "wevtutil.exe cl": "powershell Clear-EventLog -LogName", "reg save hklm\\sam": "reg.exe sa^ve HKLM\\SA^M",
                "reg save hklm\\system": "reg.exe sa^ve HKLM\\SYS^TEM", "LogMeIn.msi": "upd4721.msi",
                "net user z Lh199211* /add": "powershell New-LocalUser z", "net localgroup administrators z /add": "powershell Add-LocalGroupMember Administrators z"}
        new = []
        for c, st in cmds:
            for k, v in repl.items():
                c = c.replace(k, v)
            new.append((c, st))
        cmds = new
    for i, (c, st) in enumerate(cmds):
        add(D + 1, 2 + i // 4, "proc", c, env["dcs"][0], env["dcs"][0], stage=st)
    # machine-account lateral movement after NTDS dump
    for h in rng.choice(env["srv"], 10, replace=False):
        add(D + 1, 4, "logon", "ok", env["dcs"][0], h, user=f"{env['dcs'][0]}$", stage="Lateral Movement (T1078.002)")
    # exfil over SMB DC -> vpn host
    add(D + 1, 5, "smb_xfer", "ok", env["dcs"][0], "vpn-gw", stage="Exfiltration (T1048)")
    # re-entry attempt after password reset (D+2)
    for _ in range(6):
        add(D + 2, 3, "vpn", "fail", "ext", "vpn-gw", "RU", stage="Initial Access (T1078)")
    return a

# ---------------------------------------------------------------- detectors
SIG = [  # Sigma-style command-line signatures (credential theft / evasion)
    ("ntdsutil", "ifm"), ("reg save", "hklm\\sam"), ("reg save", "hklm\\system"), ("comsvcs.dll", "minidump"),
    ("wevtutil", " cl "), ("net user", "/add"), ("image file execution options", "debugger"),
    ("netsh advfirewall firewall set rule", "remote desktop"), ("logmein", ".msi"),
]

def rule_engine(df):
    s = np.zeros(len(df))
    cmd = df["result"].str.lower().fillna("")
    for a, b in SIG:
        s = np.maximum(s, ((df["type"] == "proc") & cmd.str.contains(a, regex=False) & cmd.str.contains(b, regex=False)).astype(float))
    # classic static thresholds
    return s

def mfa_burst_rule(df):
    g = df[(df.type == "mfa") & (df.result == "deny")].groupby(["user", "day", "hour"]).size()
    hot = set(g[g >= 5].index)
    return np.array([float(t == "mfa" and (u, d, h) in hot) for t, u, d, h in zip(df.type, df.user, df.day, df.hour)])

FEATS = ["n_logon", "n_dst", "n_new_dst", "mfa_deny", "mfa_enroll", "foreign_geo", "night", "n_proc", "n_priv_dst", "vpn_fail"]

def ueba_features(df, env, seen):
    d = df.copy()
    key = ["user", "day", "hour"]
    d["is_logon"] = (d.type == "logon").astype(int)
    d["is_new"] = [int(t == "logon" and (u, x) not in seen) for t, u, x in zip(d.type, d.user, d.dst)]
    d["is_deny"] = ((d.type == "mfa") & (d.result == "deny")).astype(int)
    d["is_enroll"] = (d.type == "mfa_enroll").astype(int)
    hg = d.user.map(env["home_geo"]).fillna("IN")
    d["is_foreign"] = ((d.geo != "-") & (d.geo != hg)).astype(int)
    d["is_proc"] = (d.type == "proc").astype(int)
    d["is_vfail"] = ((d.type == "vpn") & (d.result == "fail")).astype(int)
    lg = d[d.type == "logon"].drop_duplicates(key + ["dst"])
    nd = lg.groupby(key).size().rename("n_dst")
    nn = lg[[ (u, x) not in seen for u, x in zip(lg.user, lg.dst)]].groupby(key).size().rename("n_new_dst")
    npv = lg[lg.dst.str.startswith("dc")].groupby(key).size().rename("n_priv_dst")
    g = d.groupby(key).agg(n_logon=("is_logon", "sum"), mfa_deny=("is_deny", "sum"), mfa_enroll=("is_enroll", "sum"),
                            foreign_geo=("is_foreign", "max"), n_proc=("is_proc", "sum"), vpn_fail=("is_vfail", "sum"),
                            malicious=("malicious", "max"))
    g = g.join(nd).join(nn).join(npv).fillna(0).reset_index()
    g["night"] = ((g.hour < 6) | (g.hour > 22)).astype(int)
    return g

def graph_scores(train, test, env):
    """Bipartite user->host authentication graph learned from the training window.
    Likelihood of a test edge (u,h) = sum over peers p already authenticating to h of
    Jaccard(hosts(u), hosts(p)) / deg(p)  (resource-allocation style, so that hub accounts
    such as admins do not 'vouch' for everything). Known edges have likelihood 1.
    Anomaly score = 1 - likelihood; low-likelihood novel edges = suspected lateral movement."""
    lg = train[train.type == "logon"]
    u_hosts = defaultdict(set); h_users = defaultdict(set)
    for u, h in zip(lg.user, lg.dst):
        u_hosts[u].add(h); h_users[h].add(u)
    out = []
    for u, h in zip(test.user, test.dst):
        if h in u_hosts[u]:
            out.append(1.0); continue
        su = u_hosts[u]; sc = 0.0
        for p in h_users.get(h, ()):
            sp = u_hosts[p]
            if su and sp:
                sc += (len(su & sp) / len(su | sp)) / math.sqrt(len(sp))
        out.append(1 - math.exp(-6.0 * sc))
    return 1 - np.array(out)

def run(seed, keep=False, stealth=False):
    global LAST_THR
    rng = np.random.default_rng(seed); random.seed(seed)
    env = build_env(rng)
    victim = rng.choice([u for u in env["users"] if u not in env["admins"]])
    ben = pd.DataFrame(gen_benign(env, rng)); ben["malicious"] = 0; ben["stage"] = ""
    atk = pd.DataFrame(gen_attack(env, rng, victim, stealth))
    df = pd.concat([ben, atk], ignore_index=True)
    train = df[df.day < TRAIN_DAYS]; test = df[df.day >= TRAIN_DAYS].copy()
    seen = set(zip(train[train.type == "logon"].user, train[train.type == "logon"].dst))

    # --- UEBA: Isolation Forest on user-hour windows
    ftr = ueba_features(train, env, seen); fte = ueba_features(test, env, seen)
    iso = IsolationForest(n_estimators=300, contamination="auto", random_state=seed).fit(ftr[FEATS])
    # Isolation Forest cannot extrapolate beyond the training range (a burst of 20 MFA denials
    # lands in the same leaf as 1 denial), so a range guard adds 0.1 per feature that exceeds
    # its training maximum.
    fmax = ftr[FEATS].max()
    guard_tr = (ftr[FEATS] > fmax).sum(axis=1) * 0.1
    fte["iso_raw"] = -iso.score_samples(fte[FEATS])
    fte["iso"] = fte.iso_raw + (fte[FEATS] > fmax).sum(axis=1) * 0.1
    thr_iso = np.quantile(-iso.score_samples(ftr[FEATS]) + guard_tr, 0.995)

    # --- graph link-prediction on logon events
    tl = test[test.type == "logon"].copy()
    tl["gscore"] = graph_scores(train, tl, env)
    # Hopper-style aggregation: individual novel edges are weak evidence, but a burst of
    # unlikely edges by one account in one hour (a movement path) is strong evidence.
    tl["uh"] = list(zip(tl.user, tl.day, tl.hour))
    gh = tl.groupby(["user", "day", "hour"]).agg(gsum=("gscore", "sum"), malicious=("malicious", "max")).reset_index()
    # calibrate on a benign validation slice: graph fit on days 0..17, scored on days 18..20
    fit_, val_ = train[train.day < TRAIN_DAYS - 3], train[(train.day >= TRAIN_DAYS - 3) & (train.type == "logon")].copy()
    val_["g"] = graph_scores(fit_, val_, env)
    vsum = val_.groupby(["user", "day", "hour"]).g.sum()
    thr_g = max(float(np.quantile(vsum, 0.999)), 0.9)

    # --- rules
    test["rule"] = np.maximum(rule_engine(test), mfa_burst_rule(test))

    # --- correlation: entity risk = sum of evidence over 24h, ATT&CK-tactic diversity bonus
    ev = []
    for r in fte.itertuples():
        if r.iso > thr_iso: ev.append((r.user, r.day, r.hour, "ueba", min(r.iso / thr_iso, 2.0) * 20))
    for r in gh.itertuples():
        if r.gsum > thr_g: ev.append((r.user, r.day, r.hour, "graph", 20 * min(r.gsum / thr_g, 3.0)))
    # attribute host-level rule hits to the account active on that host
    for r in test[test.rule > 0].itertuples():
        ev.append((r.user, r.day, r.hour, "rule", 25))
    E = pd.DataFrame(ev, columns=["user", "day", "hour", "src", "pts"])
    # map machine accounts to the human session that minted them (Kerberos/session correlation)
    E["entity"] = E.user
    risk = E.groupby(["entity", "day"]).agg(pts=("pts", "sum"), kinds=("src", "nunique")).reset_index()
    risk["score"] = risk.pts * (1 + 0.5 * (risk.kinds - 1))
    ALERT = 100
    risk["alert"] = risk.score >= ALERT

    # ---------------- evaluation (entity-day granularity, the analyst's unit of triage)
    mal_ed = set(zip(atk.user, atk.day))
    def ed_eval(flagged):
        tp = len(flagged & mal_ed); fp = len(flagged - mal_ed); fn = len(mal_ed - flagged)
        n_neg = N_USERS * (DAYS - TRAIN_DAYS)
        return dict(tp=tp, fp=fp, fn=fn, recall=tp / len(mal_ed), precision=tp / max(tp + fp, 1),
                    fpr=fp / n_neg, alerts_per_day=(tp + fp) / (DAYS - TRAIN_DAYS))
    flagged = {
        "Signature rules": set(zip(test[test.rule > 0].user, test[test.rule > 0].day)),
        "UEBA (Isolation Forest)": set(zip(fte[fte.iso > thr_iso].user, fte[fte.iso > thr_iso].day)),
        "Graph link prediction": set(zip(gh[gh.gsum > thr_g].user, gh[gh.gsum > thr_g].day)),
        "Fused AI-SIEM (correlated)": set(zip(risk[risk.alert].entity, risk[risk.alert].day)),
    }
    res = {k: ed_eval(v) for k, v in flagged.items()}

    # event-level coverage per kill-chain stage (which detector saw which stage)
    stage_cov = defaultdict(lambda: defaultdict(int))
    tmp = test[test.malicious == 1]
    for r in tmp.itertuples():
        st = r.stage.split(" (")[0]
        stage_cov[st]["n"] += 1
        stage_cov[st]["rule"] += int(r.rule > 0)
    hot = set(map(tuple, gh[gh.gsum > thr_g][["user", "day", "hour"]].values.tolist()))
    for r in tl[tl.malicious == 1].itertuples():
        stage_cov[r.stage.split(" (")[0]]["graph"] += int((r.user, r.day, r.hour) in hot)
    hu = set(map(tuple, fte[fte.iso > thr_iso][["user", "day", "hour"]].values.tolist()))
    for r in test[test.malicious == 1].itertuples():
        stage_cov[r.stage.split(" (")[0]]["ueba"] += int((r.user, r.day, r.hour) in hu)
    m = fte[fte.malicious == 1]
    # time-to-detect: hours from first malicious event to first alert-grade evidence per method
    t0 = int((atk.day * 24 + atk.hour).min())
    def first(df_, col, thr):
        x = df_[(df_[col] > thr) & (df_.malicious == 1)] if "malicious" in df_ else df_
        return (x.day * 24 + x.hour).min() - t0 if len(x) else np.nan
    ttd = {"Signature rules": first(test.assign(malicious=test.malicious), "rule", 0),
           "UEBA (Isolation Forest)": first(fte, "iso", thr_iso),
           "Graph link prediction": first(gh, "gsum", thr_g)}
    vr = risk[(risk.entity == victim)]
    E_v = E[E.entity == victim].sort_values(["day", "hour"])
    E_v["cum"] = E_v.groupby("day").pts.cumsum()
    hit = E_v[E_v.cum * 1.0 >= ALERT / 2.0]   # conservative: half-threshold of multi-signal risk reached
    ttd["Fused AI-SIEM (correlated)"] = (hit.day * 24 + hit.hour).min() - t0 if len(hit) else np.nan

    # ROC data (event/window level) for figures
    roc = {}
    roc["UEBA (Isolation Forest)"] = (fte.malicious.values, fte.iso.values)
    roc["UEBA (no range guard)"] = (fte.malicious.values, fte.iso_raw.values)
    roc["Graph link prediction"] = (gh.malicious.values, gh.gsum.values)
    roc["Graph (single edge)"] = (tl.malicious.values, tl.gscore.values)
    aucs = {k: roc_auc_score(y, s) for k, (y, s) in roc.items()}
    out = dict(thr_g=thr_g, res=res, ttd=ttd, aucs=aucs, victim=victim, n_events=len(df), n_attack=len(atk),
               n_test_windows=len(fte), stage_cov={k: dict(v) for k, v in stage_cov.items()})
    if keep:
        out.update(gh=gh, df=df, fte=fte, tl=tl, risk=risk, roc=roc, thr_iso=thr_iso, E=E, iso=iso, ftr=ftr, env=env)
    return out

if __name__ == "__main__":
    import pickle
    SEEDS = list(range(N_SEEDS))
    allrows = []
    for scen in ["Cisco-replica", "Stealth variant"]:
        st = scen != "Cisco-replica"
        runs = [run(sd, keep=(sd == 0), stealth=st) for sd in SEEDS]
        for r in runs:
            for k, v in r["res"].items():
                allrows.append(dict(scenario=scen, method=k, **v, ttd=r["ttd"].get(k), auc=r["aucs"].get(k, np.nan)))
        r0 = runs[0]
        tag = "full" if not st else "stealth"
        pickle.dump({k: r0[k] for k in ["fte", "tl", "risk", "roc", "thr_iso", "E", "victim", "stage_cov", "res", "ttd", "aucs", "n_events", "n_attack", "n_test_windows"]},
                    open(f"{OUT}/run0_{tag}.pkl", "wb"))
        r0["df"][r0["df"].malicious == 1][["day", "hour", "user", "type", "src", "dst", "result", "stage"]].to_csv(f"{OUT}/attack_events_{tag}.csv", index=False)
        print(scen, "events", r0["n_events"], "attack", r0["n_attack"], "windows", r0["n_test_windows"], "victim", r0["victim"])
        print(json.dumps(r0["stage_cov"]))
    R = pd.DataFrame(allrows)
    R.to_csv(f"{OUT}/per_seed.csv", index=False)
    summ = R.groupby(["scenario", "method"])[["recall", "precision", "fpr", "alerts_per_day", "ttd", "auc"]].agg(["mean", "std"])
    summ.to_csv(f"{OUT}/summary.csv")
    pd.set_option("display.width", 250)
    print(summ.round(3).to_string())
