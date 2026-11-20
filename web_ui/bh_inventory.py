"""
BloodHound inventory for the linWinPwn Web Console.

Reads BloodHound collector output (zip, folder or loose json; bloodhound-python
legacy, SharpHound v3+ and CE layouts) and produces a DEFENSIVE report:
an inventory of the directory plus AD hygiene checks, each with the objects to
fix and a remediation note.

Scope on purpose: this module counts and describes. It does not compute attack
paths, does not rank objects by exploitability and does not reference any
offensive tooling. For attack path analysis, import the same data into
BloodHound CE.

Pure standard library.
"""
import json
import re
import time
import zipfile
from collections import defaultdict
from pathlib import Path

FILE_TYPES = {
    "users": "User", "groups": "Group", "computers": "Computer", "domains": "Domain",
    "gpos": "GPO", "ous": "OU", "containers": "Container",
    "certtemplates": "CertTemplate", "enterprisecas": "EnterpriseCA", "rootcas": "RootCA",
    "aiacas": "AIACA", "ntauthstores": "NTAuthStore", "issuancepolicies": "IssuancePolicy",
}

DAY = 86400
MAX_UNCOMPRESSED = 3 * 1024 ** 3

# Privileged groups tracked by RID or well-known SID, with why they matter.
PRIV_BY_RID = {
    "512": "Domain Admins", "519": "Enterprise Admins", "518": "Schema Admins",
    "520": "Group Policy Creator Owners", "521": "Read-only Domain Controllers",
    "516": "Domain Controllers",
}
PRIV_BY_WK = {
    "S-1-5-32-544": "Administrators", "S-1-5-32-548": "Account Operators",
    "S-1-5-32-549": "Server Operators", "S-1-5-32-550": "Print Operators",
    "S-1-5-32-551": "Backup Operators", "S-1-5-32-569": "Cryptographic Operators",
}

UNSUPPORTED_OS = re.compile(
    r"windows (xp|vista|7\b|8\b|8\.1|2000|server 2003|server 2008|server 2012)|"
    r"\b(2003|2008|2012)\b", re.I)
WIN10 = re.compile(r"windows 10", re.I)
SECRET_IN_TEXT = re.compile(
    r"pass(word|wd|phrase)?\s*[:=]|pwd\s*[:=]|mot de passe|motdepasse|\bmdp\b|"
    r"kennwort|contrase[ñn]a|\bcreds?\b\s*[:=]", re.I)


def _sid_tail(oid):
    i = oid.find("S-1-")
    return oid[i:] if i >= 0 else oid


def _rid(oid):
    t = _sid_tail(oid)
    return t.rsplit("-", 1)[-1] if t.startswith("S-1-5-21-") else None


def _days_since(v):
    """BloodHound timestamps are unix epoch; 0 and -1 mean never."""
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if v <= 0:
        return None
    return int((time.time() - v) // DAY)


def _iter_json(paths):
    """Yield (filename, bytes) for every json inside the given files/dirs/zips."""
    total = 0
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.suffix.lower() == ".json":
                    yield f.name, f.read_bytes()
                elif f.suffix.lower() == ".zip":
                    yield from _iter_json([f])
        elif p.suffix.lower() == ".zip":
            with zipfile.ZipFile(p) as z:
                for info in z.infolist():
                    if info.is_dir() or not info.filename.lower().endswith(".json"):
                        continue
                    total += info.file_size
                    if total > MAX_UNCOMPRESSED:
                        raise ValueError("archive too large (over 3 GB uncompressed)")
                    yield Path(info.filename).name, z.read(info)
        elif p.suffix.lower() == ".json":
            yield p.name, p.read_bytes()


def _detect(name, obj):
    meta = obj.get("meta") if isinstance(obj, dict) else None
    if isinstance(meta, dict) and str(meta.get("type", "")).lower() in FILE_TYPES:
        return str(meta["type"]).lower()
    low = name.lower()
    for k in FILE_TYPES:
        if low.endswith(k + ".json"):
            return k
    if isinstance(obj, dict):
        for k in FILE_TYPES:
            if isinstance(obj.get(k), list):
                return k
    return None


class Inventory:
    def __init__(self, paths, label=""):
        t0 = time.time()
        self.label = label
        self.objects = {}            # id -> {type, name, props}
        self.member_of = defaultdict(set)   # member id -> {group id}
        self.files = []
        self.collected = None
        self.domains = {}
        self.trusts = []
        self._load(paths)
        self.checks = []
        self._analyse()
        self.seconds = round(time.time() - t0, 2)

    # ---------------- loading ----------------
    def _load(self, paths):
        for name, raw in _iter_json(paths):
            try:
                obj = json.loads(raw.decode("utf-8-sig"))
            except Exception:
                continue
            ftype = _detect(name, obj)
            if not ftype:
                continue
            data = obj.get("data")
            if data is None:
                data = obj.get(ftype, [])
            if not isinstance(data, list):
                continue
            meta = obj.get("meta") or {}
            when = meta.get("collectionDate") or meta.get("CollectionDate")
            if when and not self.collected:
                self.collected = when
            self.files.append({"name": name, "type": ftype, "count": len(data)})
            for o in data:
                if isinstance(o, dict):
                    self._object(ftype, o)
        if not self.objects:
            raise ValueError(
                "no BloodHound data found. Expected a collector zip or *_users.json, "
                "*_computers.json, *_groups.json ... files.")

    def _object(self, ftype, o):
        ntype = FILE_TYPES[ftype]
        raw = o.get("Properties") or {}
        props = {str(k).lower(): v for k, v in raw.items()}
        oid = o.get("ObjectIdentifier") or props.get("objectid") or o.get("ObjectSid")
        if not oid:
            return
        oid = str(oid).upper()
        self.objects[oid] = {"type": ntype, "name": props.get("name") or oid, "props": props}

        if ntype == "Domain":
            self.domains[oid] = props.get("name") or oid
            for t in o.get("Trusts") or []:
                self.trusts.append({
                    "domain": props.get("name") or oid,
                    "target": t.get("TargetDomainName") or t.get("TargetDomainSid"),
                    "direction": t.get("TrustDirection"),
                    "type": t.get("TrustType"),
                    "transitive": t.get("IsTransitive"),
                    "sidfiltering": t.get("SidFilteringEnabled"),
                })

        # group membership (needed to size privileged groups)
        if ntype == "Group":
            for m in o.get("Members") or []:
                mid = m.get("ObjectIdentifier") if isinstance(m, dict) else m
                if mid:
                    self.member_of[str(mid).upper()].add(oid)
        pg = o.get("PrimaryGroupSID") or props.get("primarygroupsid")
        if pg:
            self.member_of[oid].add(str(pg).upper())

    # ---------------- helpers ----------------
    def name(self, oid):
        return (self.objects.get(oid) or {}).get("name", oid)

    def typ(self, oid):
        return (self.objects.get(oid) or {}).get("type", "Base")

    def prop(self, oid, key, default=None):
        return (self.objects.get(oid) or {}).get("props", {}).get(key, default)

    def enabled(self, oid):
        return self.prop(oid, "enabled") is not False

    def of_type(self, t, enabled_only=False):
        return [i for i, n in self.objects.items()
                if n["type"] == t and (not enabled_only or self.enabled(i))]

    def group_members(self, gid, types=None, _seen=None):
        """Recursive members of a group (used only to size privileged groups)."""
        seen = _seen if _seen is not None else set()
        out = set()
        for mid, groups in self.member_of.items():
            if gid not in groups or mid in seen:
                continue
            seen.add(mid)
            if self.typ(mid) == "Group":
                out |= self.group_members(mid, types, seen)
            elif not types or self.typ(mid) in types:
                out.add(mid)
        return out

    def find_groups(self):
        """Privileged groups present in the data -> {id: label}."""
        found = {}
        for oid in self.objects:
            if self.typ(oid) != "Group":
                continue
            label = PRIV_BY_RID.get(_rid(oid) or "") or PRIV_BY_WK.get(_sid_tail(oid))
            if label:
                found[oid] = label
        return found

    def add(self, cid, sev, title, items, why, fix, total=None):
        """Record a hygiene check. items: list of dicts or object ids."""
        rows = []
        for o in items[:500]:
            if isinstance(o, dict):
                rows.append(o)
            else:
                rows.append({"id": o, "name": self.name(o), "type": self.typ(o)})
        self.checks.append({
            "id": cid, "severity": sev, "title": title,
            "count": len(items), "total": total,
            "pct": (round(100 * len(items) / total) if total else None),
            "items": rows, "truncated": len(items) > len(rows),
            "why": why, "fix": fix,
        })

    # ---------------- checks ----------------
    def _analyse(self):
        users_all = self.of_type("User")
        users = self.of_type("User", True)
        comps_all = self.of_type("Computer")
        comps = self.of_type("Computer", True)
        nu, nc = len(users), len(comps)

        # --- account lifecycle -------------------------------------------------
        stale = []
        never = []
        for u in users:
            if self.name(u).upper().startswith(("KRBTGT@", "GUEST@")):
                continue
            d = _days_since(self.prop(u, "lastlogontimestamp"))
            if d is None:
                never.append({"id": u, "name": self.name(u), "type": "User",
                              "detail": "never logged on"})
            elif d > 90:
                stale.append({"id": u, "name": self.name(u), "type": "User",
                              "detail": f"last logon {d} days ago", "sort": d})
        stale.sort(key=lambda r: -r["sort"])
        if stale:
            self.add("stale", "medium", "Enabled accounts inactive for over 90 days", stale,
                     "Dormant but enabled accounts stay usable and nobody notices when they are. "
                     "They are the accounts most often forgotten in password rotations.",
                     "Disable them, then delete after a retention period. Automate with a scheduled review.", nu)
        if never:
            self.add("never", "medium", "Enabled accounts that never logged on", never,
                     "Accounts created and never used. Often test or service accounts left behind.",
                     "Confirm with the owner, then disable or delete.", nu)
        disabled = [u for u in users_all if not self.enabled(u)]
        if disabled:
            self.add("disabled", "info", "Disabled accounts", disabled,
                     "Normal to have some. Worth cleaning if the number keeps growing.",
                     "Delete after your retention period.", len(users_all))

        # --- password hygiene ---------------------------------------------------
        pne = [u for u in users if self.prop(u, "pwdneverexpires")]
        if pne:
            self.add("pwdneverexpires", "medium", "Passwords set to never expire", pne,
                     "A password that never changes stays valid for years, including after a leak "
                     "or after someone leaves.",
                     "Remove DONT_EXPIRE_PASSWORD. For service accounts, move to gMSA so Windows "
                     "rotates the password automatically.", nu)
        pnr = [u for u in users if self.prop(u, "passwordnotreqd")]
        if pnr:
            self.add("passwordnotreqd", "high", "Accounts that do not require a password", pnr,
                     "PASSWD_NOTREQD lets the account keep an empty password, whatever the domain policy says.",
                     "Clear the flag and set a password on each account.", nu)
        old_pw = []
        for u in users:
            if _rid(u) == "502":          # krbtgt has its own check below
                continue
            d = _days_since(self.prop(u, "pwdlastset"))
            if d is not None and d > 365:
                old_pw.append({"id": u, "name": self.name(u), "type": "User",
                               "detail": f"password set {d} days ago", "sort": d})
        old_pw.sort(key=lambda r: -r["sort"])
        if old_pw:
            self.add("oldpw", "medium", "Passwords older than one year", old_pw,
                     "Long-lived passwords are the ones that end up in breach dumps and in shared notes.",
                     "Rotate them and keep a maximum password age in the domain policy.", nu)

        # --- service accounts ----------------------------------------------------
        spn = [u for u in users if self.prop(u, "hasspn")
               and not self.name(u).upper().startswith("KRBTGT@")]
        if spn:
            rows = []
            for u in spn:
                d = _days_since(self.prop(u, "pwdlastset"))
                rows.append({"id": u, "name": self.name(u), "type": "User",
                             "detail": (f"password {d} days old" if d is not None else "password age unknown")
                                       + (" · never expires" if self.prop(u, "pwdneverexpires") else "")})
            self.add("spn", "medium", "User accounts registered as services (SPN)", rows,
                     "A service running under a normal user account has a password a human chose, "
                     "and any domain member can request a Kerberos ticket for it. That ticket can be "
                     "attacked offline, so the password strength is the only protection.",
                     "Move these services to group Managed Service Accounts (gMSA): Windows then uses a "
                     "random 240-character password and rotates it. Where gMSA is not possible, set a "
                     "25+ character random password and remove SPNs that are no longer used.", nu)
        nopreauth = [u for u in users if self.prop(u, "dontreqpreauth")]
        if nopreauth:
            self.add("nopreauth", "high", "Accounts with Kerberos pre-authentication disabled", nopreauth,
                     "Pre-authentication is what stops anyone from asking the DC for material tied to "
                     "the account password without proving anything first.",
                     "Clear DONT_REQ_PREAUTH on every account. If an old application needs it, "
                     "isolate it and give the account a long random password.", nu)

        # --- privileged groups ----------------------------------------------------
        priv = self.find_groups()
        rows = []
        sizes = []
        da_total = 0
        for gid, label in sorted(priv.items(), key=lambda kv: kv[1]):
            mem = [m for m in self.group_members(gid, {"User"}) if self.enabled(m)]
            sizes.append({"group": label, "count": len(mem)})
            if label == "Domain Admins":
                da_total += len(mem)
            for m in mem:
                d = _days_since(self.prop(m, "lastlogontimestamp"))
                flags = []
                if self.prop(m, "pwdneverexpires"):
                    flags.append("password never expires")
                if not self.prop(m, "sensitive"):
                    flags.append("delegatable")
                if d is not None and d > 90:
                    flags.append(f"inactive {d}d")
                rows.append({"id": m, "name": self.name(m), "type": "User",
                             "detail": label + (" · " + ", ".join(flags) if flags else "")})
        if rows:
            self.add("privmembers", "high" if da_total > 10 else "info",
                     "Members of privileged groups", rows,
                     f"{da_total} enabled Domain Admins. Every privileged account is one more "
                     "credential that must never be exposed on a workstation.",
                     "Keep Domain Admins in the single digits. Give admins a separate account used "
                     "only on hardened hosts, and add them to Protected Users.")
        self.priv_sizes = sorted(sizes, key=lambda r: -r["count"])

        t0_users = set()
        for gid, label in priv.items():
            if label in ("Domain Admins", "Enterprise Admins", "Administrators", "Schema Admins"):
                t0_users |= self.group_members(gid, {"User"})
        t0_users = {u for u in t0_users if self.enabled(u)}
        delegable = [u for u in t0_users if not self.prop(u, "sensitive")
                     and _rid(u) != "502"]
        if delegable:
            self.add("delegable", "medium", "Admin accounts not marked sensitive", delegable,
                     "Without the 'sensitive and cannot be delegated' flag (or Protected Users "
                     "membership), an admin's Kerberos ticket can be reused by a service the admin "
                     "connects to.",
                     "Tick 'Account is sensitive and cannot be delegated', or add the accounts to "
                     "the Protected Users group.", len(t0_users) or None)

        krbtgt = []
        for u in self.of_type("User"):
            if _rid(u) != "502":
                continue
            d = _days_since(self.prop(u, "pwdlastset"))
            if d is not None and d > 180:
                krbtgt.append({"id": u, "name": self.name(u), "type": "User",
                               "detail": f"password set {d} days ago"})
        if krbtgt:
            self.add("krbtgt", "medium", "krbtgt password not rotated recently", krbtgt,
                     "The krbtgt key signs every Kerberos ticket in the domain. If it ever leaked, "
                     "tickets forged with it stay valid until the key is changed twice.",
                     "Reset the krbtgt password twice, waiting for full replication between the two "
                     "resets. Microsoft publishes a script for this.")

        # --- delegation -----------------------------------------------------------
        dc_ids = {c for c in comps_all if self.prop(c, "isdc")}
        for gid, label in priv.items():
            if label == "Domain Controllers":
                dc_ids |= self.group_members(gid, {"Computer"})
        uncon = [i for i in comps + users
                 if self.prop(i, "unconstraineddelegation") and i not in dc_ids]
        if uncon:
            self.add("unconstrained", "high", "Unconstrained delegation outside domain controllers",
                     [{"id": i, "name": self.name(i), "type": self.typ(i)} for i in uncon],
                     "These hosts receive and store a full Kerberos ticket for every user who "
                     "connects to them, including administrators. One compromised host then holds "
                     "credentials it was never meant to hold.",
                     "Replace with constrained or resource-based constrained delegation, which limits "
                     "the services the host can reach.")
        con = []
        for i in comps + users:
            tgts = self.prop(i, "allowedtodelegate")
            if tgts:
                con.append({"id": i, "name": self.name(i), "type": self.typ(i),
                            "detail": ", ".join(map(str, tgts[:3]))
                                      + (" · protocol transition" if self.prop(i, "trustedtoauth") else "")})
        if con:
            self.add("constrained", "info", "Constrained delegation configured", con,
                     "Legitimate when intended. Worth reviewing: each entry lets the account act as "
                     "other users towards the listed services.",
                     "Confirm every entry is still needed and that the target list is as narrow as possible.")

        # --- machines ----------------------------------------------------------------
        os_count = defaultdict(int)
        for c in comps:
            os_count[str(self.prop(c, "operatingsystem") or "unknown")] += 1
        self.os_breakdown = sorted(({"os": k, "count": v} for k, v in os_count.items()),
                                   key=lambda r: -r["count"])
        unsup = [{"id": c, "name": self.name(c), "type": "Computer",
                  "detail": str(self.prop(c, "operatingsystem"))}
                 for c in comps if UNSUPPORTED_OS.search(str(self.prop(c, "operatingsystem") or ""))]
        if unsup:
            self.add("unsupported_os", "high", "Unsupported operating systems", unsup,
                     "No security updates. Known vulnerabilities stay open permanently, and these "
                     "hosts usually also lack modern protections like SMB signing or Credential Guard.",
                     "Upgrade. Where a system cannot move, isolate it on its own network segment with "
                     "strict firewall rules and no domain admin logons.", nc)
        w10 = [{"id": c, "name": self.name(c), "type": "Computer",
                "detail": str(self.prop(c, "operatingsystem"))}
               for c in comps if WIN10.search(str(self.prop(c, "operatingsystem") or ""))]
        if w10:
            self.add("win10", "medium", "Windows 10 (mainstream support ended October 2025)", w10,
                     "Only covered if the organisation pays for Extended Security Updates.",
                     "Plan the move to Windows 11, or budget for ESU.", nc)
        has_laps_data = any(self.prop(c, "haslaps") is not None for c in comps)
        if has_laps_data:
            nolaps = [c for c in comps if not self.prop(c, "haslaps") and c not in dc_ids]
            if nolaps:
                self.add("nolaps", "high", "Computers without LAPS", nolaps,
                         "Without LAPS the local administrator password is usually identical across "
                         "machines, so one recovered password opens all of them.",
                         "Deploy Windows LAPS and let it randomise and rotate the local admin password "
                         "per machine.", nc)
        stale_c = []
        for c in comps:
            d = _days_since(self.prop(c, "lastlogontimestamp"))
            if d is not None and d > 90:
                stale_c.append({"id": c, "name": self.name(c), "type": "Computer",
                                "detail": f"last seen {d} days ago", "sort": d})
        stale_c.sort(key=lambda r: -r["sort"])
        if stale_c:
            self.add("stale_computers", "low", "Computer accounts inactive for over 90 days", stale_c,
                     "Machines that no longer exist but still have a valid account in the domain.",
                     "Disable, then delete after a retention period.", nc)

        # --- data left in attributes ---------------------------------------------------
        leaks = []
        for i in list(users) + list(comps):
            desc = self.prop(i, "description")
            if isinstance(desc, str) and SECRET_IN_TEXT.search(desc):
                leaks.append({"id": i, "name": self.name(i), "type": self.typ(i), "detail": desc})
        if leaks:
            self.add("description", "high", "Possible credentials in description fields", leaks,
                     "Every authenticated user can read the description attribute of every object.",
                     "Remove the text and rotate anything that was written there. Store secrets in a "
                     "password manager instead.")

        # --- domain -------------------------------------------------------------------
        fl = [{"id": d, "name": self.name(d), "type": "Domain",
               "detail": f"functional level {self.prop(d, 'functionallevel')}"}
              for d in self.domains
              if re.search(r"2000|2003|2008|2012", str(self.prop(d, "functionallevel") or ""))]
        if fl:
            self.add("functionallevel", "medium", "Old domain functional level", fl,
                     "Older levels miss protections such as Protected Users, Authentication Policies "
                     "and modern Kerberos defaults.",
                     "Raise the domain and forest functional level once all DCs support it.")
        if self.trusts:
            nofilter = [t for t in self.trusts if t.get("sidfiltering") is False]
            self.add("trusts", "medium" if nofilter else "info", "Domain trusts",
                     [{"name": f"{t['domain']} → {t['target']}", "type": "Trust",
                       "detail": f"direction {t.get('direction')} · type {t.get('type')} · "
                                 f"SID filtering {t.get('sidfiltering')}"} for t in self.trusts],
                     "A trust extends your security boundary to another domain: its compromise can "
                     "become yours." + (" Some trusts have SID filtering disabled." if nofilter else ""),
                     "Review whether each trust is still needed. Enable SID filtering and consider "
                     "selective authentication.")

        # --- certificate services ----------------------------------------------------
        cas = self.of_type("EnterpriseCA")
        if cas:
            san = [c for c in cas if self.prop(c, "isuserspecifiessanenabled")]
            if san:
                self.add("ca_san", "high", "CA accepts a subject supplied in the request", san,
                         "With EDITF_ATTRIBUTESUBJECTALTNAME2 set, a certificate request can name any "
                         "account as its subject, so an issued certificate can identify someone else.",
                         "Remove the flag on the CA (certutil -setreg policy\\EditFlags "
                         "-EDITF_ATTRIBUTESUBJECTALTNAME2) and restart the CA service.")
            self.add("ca_inventory", "info", "Certificate authorities",
                     [{"id": c, "name": self.name(c), "type": "EnterpriseCA"} for c in cas],
                     "Certificate services are an authentication path into the domain and deserve the "
                     "same protection as a domain controller.",
                     "Keep CAs patched, restrict who can manage them, and review published templates "
                     "regularly.")
        tmpl = self.of_type("CertTemplate")
        if tmpl:
            weak = [{"id": t, "name": self.name(t), "type": "CertTemplate",
                     "detail": "subject supplied in request"
                               + ("" if self.prop(t, "requiresmanagerapproval") else " · no manager approval")}
                    for t in tmpl if self.prop(t, "enrolleesuppliessubject")]
            if weak:
                self.add("tmpl_san", "high", "Templates where the requester chooses the subject", weak,
                         "If such a template also allows client authentication, a certificate can be "
                         "issued in someone else's name.",
                         "Build the subject from Active Directory instead, or require manager approval "
                         "on the template.", len(tmpl))

        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        self.checks.sort(key=lambda c: (order[c["severity"]], -c["count"]))

        self.stats = {
            "domains": list(self.domains.values()),
            "collected": self.collected,
            "users": len(users_all), "users_enabled": nu,
            "computers": len(comps_all), "computers_enabled": nc,
            "groups": len(self.of_type("Group")),
            "ous": len(self.of_type("OU")),
            "gpos": len(self.of_type("GPO")),
            "dcs": len(dc_ids),
            "domain_admins": da_total,
            "objects": len(self.objects),
            "files": self.files,
        }

    # ---------------- output ----------------
    def report(self):
        sev = defaultdict(int)
        for c in self.checks:
            sev[c["severity"]] += 1
        return {
            "label": self.label,
            "stats": self.stats,
            "severity": dict(sev),
            "privileged_groups": self.priv_sizes,
            "os_breakdown": self.os_breakdown,
            "checks": self.checks,
            "seconds": self.seconds,
        }
