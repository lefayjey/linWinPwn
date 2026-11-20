"""Self-contained tests for bh_inventory: builds a synthetic BloodHound
collection, runs the inventory, and asserts each hygiene check fires on the
objects it should.

    python3 web_ui/tests/test_bh_inventory.py
"""
import json
import os
import sys
import tempfile
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from bh_inventory import Inventory          # noqa: E402

DOM = "TEST.LOCAL"
SID = "S-1-5-21-10-20-30"
NOW = int(time.time())
DAY = 86400
ok, failed = 0, 0


def check(name, cond, info=""):
    global ok, failed
    if cond:
        ok += 1
        print(f"PASS  {name}" + (f"  ({info})" if info else ""))
    else:
        failed += 1
        print(f"FAIL  {name}" + (f"  ({info})" if info else ""))


def ts(days):
    return NOW - days * DAY


def build(path):
    def user(name, rid, **p):
        props = {"name": f"{name}@{DOM}", "objectid": f"{SID}-{rid}", "domain": DOM,
                 "enabled": p.get("enabled", True),
                 "lastlogontimestamp": p.get("logon", ts(2)),
                 "pwdlastset": ts(p.get("pwdage", 30))}
        for k in ("pwdneverexpires", "passwordnotreqd", "dontreqpreauth", "hasspn",
                  "unconstraineddelegation", "sensitive", "description", "allowedtodelegate"):
            if k in p:
                props[k] = p[k]
        return {"ObjectIdentifier": f"{SID}-{rid}", "Properties": props, "Aces": [],
                "PrimaryGroupSID": f"{SID}-513"}

    def comp(name, rid, osname, **p):
        props = {"name": f"{name}.{DOM}", "objectid": f"{SID}-{rid}", "domain": DOM,
                 "enabled": True, "operatingsystem": osname,
                 "lastlogontimestamp": p.get("logon", ts(1)), "pwdlastset": ts(10),
                 "haslaps": p.get("laps", True)}
        for k in ("unconstraineddelegation", "isdc", "description"):
            if k in p:
                props[k] = p[k]
        return {"ObjectIdentifier": f"{SID}-{rid}", "Properties": props, "Aces": []}

    users = [
        user("alice", 1001),
        user("bob", 1002, logon=ts(400)),                       # stale
        user("carol", 1003, logon=0),                           # never logged on
        user("dave", 1004, pwdneverexpires=True),
        user("erin", 1005, passwordnotreqd=True),
        user("frank", 1006, pwdage=500),                        # old password
        user("svc_sql", 1007, hasspn=True, pwdage=700),
        user("legacy", 1008, dontreqpreauth=True),
        user("leaky", 1009, description="svc account password: Hunter2!"),
        user("admin1", 1010),                                   # Domain Admin, not sensitive
        user("admin2", 1011, sensitive=True),                   # Domain Admin, sensitive
        user("krbtgt", 502, pwdage=900),
        user("olduser", 1012, enabled=False),                   # disabled
    ]
    comps = [
        comp("DC01", 2001, "Windows Server 2022 Datacenter", isdc=True,
             unconstraineddelegation=True, laps=False),         # DC: must NOT be flagged
        comp("SRV1", 2002, "Windows Server 2019 Standard", unconstraineddelegation=True),
        comp("SRV2", 2003, "Windows Server 2008 R2", laps=False),   # unsupported + no LAPS
        comp("WS1", 2004, "Windows 10 Enterprise"),
        comp("WS2", 2005, "Windows 11 Enterprise", logon=ts(200)),  # stale computer
    ]
    groups = [
        {"ObjectIdentifier": f"{SID}-512",
         "Properties": {"name": f"DOMAIN ADMINS@{DOM}", "objectid": f"{SID}-512"},
         "Members": [{"ObjectIdentifier": f"{SID}-1010", "ObjectType": "User"},
                     {"ObjectIdentifier": f"{SID}-1011", "ObjectType": "User"}], "Aces": []},
        {"ObjectIdentifier": f"{SID}-516",
         "Properties": {"name": f"DOMAIN CONTROLLERS@{DOM}", "objectid": f"{SID}-516"},
         "Members": [{"ObjectIdentifier": f"{SID}-2001", "ObjectType": "Computer"}], "Aces": []},
    ]
    domains = [{"ObjectIdentifier": SID,
                "Properties": {"name": DOM, "objectid": SID, "functionallevel": "2008 R2"},
                "Trusts": [{"TargetDomainName": "OTHER.LOCAL", "TrustDirection": "Inbound",
                            "TrustType": "External", "SidFilteringEnabled": False}], "Aces": []}]
    cas = [{"ObjectIdentifier": "CA1",
            "Properties": {"name": f"CA@{DOM}", "objectid": "CA1",
                           "isuserspecifiessanenabled": True}, "Aces": []}]
    tmpl = [{"ObjectIdentifier": "T1",
             "Properties": {"name": f"TPL@{DOM}", "objectid": "T1",
                            "enrolleesuppliessubject": True,
                            "requiresmanagerapproval": False}, "Aces": []}]

    files = {"users": users, "computers": comps, "groups": groups, "domains": domains,
             "enterprisecas": cas, "certtemplates": tmpl}
    names = []
    for t, data in files.items():
        fn = os.path.join(path, f"2026_{t}.json")
        json.dump({"meta": {"type": t, "count": len(data), "version": 5,
                            "collectionDate": "2026-11-20T10:00:00Z"}, "data": data},
                  open(fn, "w"))
        names.append(fn)
    zp = os.path.join(path, "collection.zip")
    with zipfile.ZipFile(zp, "w") as z:
        for fn in names:
            z.write(fn, os.path.basename(fn))
    return zp


def names_in(rep, cid):
    for c in rep["checks"]:
        if c["id"] == cid:
            return {i["name"].split("@")[0].split(".")[0] for i in c["items"]}
    return set()


def main():
    tmp = tempfile.mkdtemp()
    zp = build(tmp)

    rep = Inventory([zp], "test").report()
    st = rep["stats"]

    check("inventory counts", st["users"] == 13 and st["users_enabled"] == 12
          and st["computers"] == 5 and st["dcs"] == 1,
          f"{st['users_enabled']}/{st['users']} users, {st['computers']} computers, {st['dcs']} DC")
    check("domain and collection date", st["domains"] == [DOM] and st["collected"],
          st["domains"][0] if st["domains"] else "none")
    check("domain admins counted", st["domain_admins"] == 2, str(st["domain_admins"]))

    check("stale accounts", names_in(rep, "stale") == {"bob"}, names_in(rep, "stale"))
    check("never logged on", names_in(rep, "never") == {"carol"}, names_in(rep, "never"))
    check("disabled accounts", names_in(rep, "disabled") == {"olduser"})
    check("password never expires", "dave" in names_in(rep, "pwdneverexpires"))
    check("password not required", names_in(rep, "passwordnotreqd") == {"erin"})
    check("old passwords (krbtgt excluded)",
          "frank" in names_in(rep, "oldpw") and "krbtgt" not in names_in(rep, "oldpw"),
          names_in(rep, "oldpw"))
    check("SPN accounts", names_in(rep, "spn") == {"svc_sql"})
    check("no pre-auth", names_in(rep, "nopreauth") == {"legacy"})
    check("credentials in description", names_in(rep, "description") == {"leaky"})
    check("krbtgt rotation", names_in(rep, "krbtgt") == {"krbtgt"})
    check("admin not sensitive (only admin1)", names_in(rep, "delegable") == {"admin1"},
          names_in(rep, "delegable"))
    check("privileged members listed", names_in(rep, "privmembers") == {"admin1", "admin2"})

    check("unconstrained delegation skips DCs",
          names_in(rep, "unconstrained") == {"SRV1"}, names_in(rep, "unconstrained"))
    check("unsupported OS", names_in(rep, "unsupported_os") == {"SRV2"})
    check("Windows 10", names_in(rep, "win10") == {"WS1"})
    check("no LAPS skips DCs", names_in(rep, "nolaps") == {"SRV2"}, names_in(rep, "nolaps"))
    check("stale computers", names_in(rep, "stale_computers") == {"WS2"})

    check("old functional level", len(names_in(rep, "functionallevel")) == 1)
    check("trusts flagged (no SID filtering)",
          any(c["id"] == "trusts" and c["severity"] == "medium" for c in rep["checks"]))
    check("CA SAN flag", names_in(rep, "ca_san") == {"CA"})
    check("template subject in request", names_in(rep, "tmpl_san") == {"TPL"})

    sevs = {c["severity"] for c in rep["checks"]}
    check("severities valid", sevs <= {"high", "medium", "low", "info"}, sevs)
    check("sorted by severity",
          [c["severity"] for c in rep["checks"]] ==
          sorted((c["severity"] for c in rep["checks"]),
                 key=lambda s: {"high": 0, "medium": 1, "low": 2, "info": 3}[s]))
    check("every check has why and fix",
          all(c["why"] and c["fix"] for c in rep["checks"]))

    # same data, loose folder instead of zip
    rep2 = Inventory([tmp], "folder").report()
    check("folder and zip give the same result",
          len(rep2["checks"]) == len(rep["checks"])
          and rep2["stats"]["users"] == st["users"])

    # defensive scope: no offensive tooling referenced anywhere
    blob = json.dumps(rep).lower()
    bad = [w for w in ("kerberoast", "dcsync", "attack path", "secretsdump",
                       "lsass", "impacket", "netexec", "shortest path", "exploit")
           if w in blob]
    check("no offensive tooling referenced", not bad, ", ".join(bad))

    for bad_input, label in (([tempfile.mkdtemp()], "empty folder"),):
        try:
            Inventory(bad_input, label)
            check(f"rejects {label}", False)
        except ValueError:
            check(f"rejects {label}", True)

    print(f"\n{ok}/{ok + failed} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
