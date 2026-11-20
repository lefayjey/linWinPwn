"""Check that every dashboard button in menus.json matches a real option of
linWinPwn.sh, and list script options missing from the dashboard.
Reads the script only, runs nothing.

    python3 web_ui/tests/check_menus.py
"""
import os
import json, re, sys
HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "linWinPwn.sh")
MENUS = sys.argv[2] if len(sys.argv) > 2 else os.path.join(HERE, "..", "menus.json")
src = open(SCRIPT).read().split("\n")
menus = json.load(open(MENUS))["menus"]
HEADER = {"AD Enum menu":"ad","ADCS menu":"adcs","SCCM menu":"sccm","GPO menu":"gpo","BruteForce menu":"brute",
  "Kerberos Attacks menu":"kerberos","SMB Shares menu":"shares","Vuln Checks menu":"vulns","MSSQL Enumeration menu":"mssql",
  "Password Dump menu":"pwd","Modification menu":"modif","Command Execution menu":"cmdexec","Network Scan menu":"netscan",
  "Auth menu":"auth","Config menu":"config","Main menu":"main"}
# split into *_menu() functions, keep their header + top-level case labels
funcs, cur = {}, None
for line in src:
    m = re.match(r"^(\w+_menu)\(\)\s*\{", line)
    if m: cur = m.group(1); funcs[cur] = []; continue
    if cur:
        if line.startswith("}"): cur = None; continue
        funcs[cur].append(line)
labels = {}
for fn, body in funcs.items():
    txt = "\n".join(body)
    h = re.search(r"\[([A-Za-z0-9 ]+ menu)\]", txt)
    if not h or h.group(1) not in HEADER: continue
    keys = set()
    for l in body:
        m = re.match(r"^\s{4,12}([A-Za-z0-9|\"*]+)\)\s*$", l)
        if m:
            for k in m.group(1).replace('"','').split("|"): keys.add(k)
    labels[HEADER[h.group(1)]] = keys
bad, n = [], 0
for m in menus:
    if m.get("direct"):
        n += 1
        if m["enter"] not in labels["main"]: bad.append(("main", m["enter"], m["title"]))
        continue
    if m["enter"] not in labels["main"]: bad.append(("main", m["enter"], m["title"]+" (enter)"))
    if m["id"] not in labels: bad.append((m["id"], "-", "menu function not found")); continue
    for a in m["actions"]:
        n += 1
        if a["key"] not in labels[m["id"]]: bad.append((m["id"], a["key"], a["label"]))
# options in the script that the dashboard does not expose
missing = []
for mid, keys in labels.items():
    if mid == "main": continue
    mm = next((x for x in menus if x["id"] == mid), None)
    have = {a["key"] for a in mm["actions"]} if mm else set()
    for k in sorted(keys - have - {"back", "exit", "*", "q"}):
        if mid == "auth" and k == "A":   # empty case in the script, not a real option
            continue
        missing.append((mid, k))
print(f"checked {n} dashboard buttons against {len(labels)} script menus")
print("   buttons with no matching case in the script:", bad or "none")
print("   script options not in the dashboard:", missing or "none")
sys.exit(1 if bad else 0)
