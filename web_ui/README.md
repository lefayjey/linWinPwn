# linWinPwn Web Console

A web dashboard for [linWinPwn](https://github.com/lefayjey/linWinPwn). Every menu and every option of the script (16 menus, 238 actions) is a button, and there is a real embedded shell next to it.

Everything is done from the web: you pick menus and options with buttons, and every question the script asks is answered in a web form. The terminal only shows the output (typing in it is optional, behind the "type in terminal" checkbox).

The dashboard does not rewrite any linWinPwn logic. The backend starts the real `linWinPwn.sh` inside a pseudo terminal, the buttons send the same keys you would type, and the browser reads the output to know what the script is waiting for.

## Features

- **Session form**: target DC, domain, user, and the 5 auth methods (password, NTLM hash, Kerberos ticket, AES key, PFX cert), plus every CLI flag (`--ldaps`, `--ldap-sign`, `--ldap-bind`, `--force-kerb`, `--use-ip`, `--dns-tcp`, `--auto-config`, `--verbose`, `--no-exec`, `--offline`, `--auto`, `-T`, `-I`, `-a`, wordlists, output dir...).
- **Module sidebar**: all menus with a filter box. Each action has badges: `noisy`, `batch` (the `A` option of each menu), `prompts` (asks questions) and `console` (opens an interactive tool).
- **Web forms for every question**: the UI reads the output and shows the right form under it:
  - text question, with the default value shown and a "Use default" button (`press Enter to choose default value ...`)
  - password / hash / key fields are masked (with a show button)
  - yes / no (`y/N`) and two-choice questions (`'RC4' or 'AES'`) become buttons
  - values listed above a question (for example your IPs) become clickable suggestions
  - numbered lists (Modify target(s), LDAPPER options...) become buttons, plus a free text field
  - `press ENTER to continue` becomes a "Continue" button
  - tool consoles (evil-winrm, smbclient, mssqlclient, LDAP console...) get a command field
- **Run state**: `ready` (at a menu, buttons active), `running…`, `waiting for your answer`. The UI also reads the menu headers (`[AD Enum menu]`...) so it always knows which menu the script is in.
- **■ Stop**: works like Ctrl+C on the running command only. You stay in the same menu and the session keeps running. If the tool ignores the signal it is forced after 3 to 5 seconds. (A real Ctrl+C would kill linWinPwn itself, since the script has no handler for it.)
- **⟲ reset**: restarts the whole session with the same config, also after a page reload.
- **Offline preview with your creds**: tick `Offline` + `No-exec` and fill the credentials: the script prints the exact commands it would run with them, without touching any target.
- **Command history**: every command linWinPwn runs (already masked by the script), with copy buttons.
- **linWinPwn terminal**: live output of the script (xterm.js, colors kept).
- **Embedded shell**: a separate bash in the repo folder, for manual commands (netexec, impacket, certipy...). It keeps running when you switch tabs.
- **Output / loot**: read-only browser of the output folder, with preview and download.
- **BloodHound tab**: load a collection (the zip linWinPwn produces, a folder of `*_users.json`, or a single json) and get an inventory of the directory plus the AD hygiene problems worth fixing, each with the objects concerned and a remediation note. Export the whole thing as Markdown for a report. See the section below for what it does and does not do.
- Secrets (`-p`, `-H`, `-A`, `--cert-pass`) are hidden in the command line shown back in the UI.

## Run it

Put the `web_ui/` folder next to `linWinPwn.sh` (it already is in this repo), then:

```bash
./web_ui/run.sh
```

The first run creates a virtualenv and installs Flask. The script prints a URL with a random token:

```
http://127.0.0.1:8777/?token=<token>
```

Options: `./web_ui/run.sh --port 9000`, or set your own token with `LWP_WEB_TOKEN=mytoken ./web_ui/run.sh`.

### Docker

```bash
docker build -f web_ui/Dockerfile.webui -t linwinpwn-webui .
docker run --rm -it --net=host \
  -e LWP_WEB_TOKEN=change-me \
  -v "$(pwd)/lwp-output:/opt/linWinPwn/lwp-output" \
  linwinpwn-webui
# open http://127.0.0.1:8777/?token=change-me
```

## How a button works

Action buttons are active only when the script is back at a menu (`ready`). The UI knows the current menu from the script's own headers:

- Action in the menu you are already in: it sends only the action key (e.g. `1`).
- Action in another menu: it sends `back`, then the menu number, then the action key.
- **⌂ main menu** goes back to the main menu.

If you type in the terminal yourself, the UI still follows, since it reads the headers.

## BloodHound tab

Drop a collection on the tab, or pick one it finds in your output folder, and you get:

- **Inventory**: users, computers, groups, OUs, GPOs, domain controllers, Domain Admins, with enabled vs total; size of each privileged group; breakdown of operating systems (obsolete ones in orange).
- **Hygiene checks**, sorted by severity, each with why it matters, what to do about it, and the list of objects concerned: stale and never-used accounts, passwords that never expire or are over a year old, accounts that do not require a password, Kerberos pre-authentication disabled, user accounts used as services (SPN), privileged group membership, admin accounts not marked sensitive, krbtgt rotation, unconstrained and constrained delegation, unsupported operating systems, Windows 10 end of support, computers without LAPS, credentials left in description fields, domain functional level, trusts without SID filtering, and certificate services (CA accepting a requester-supplied subject, templates where the requester chooses the subject).
- **Export** as Markdown, with the full object lists, ready to paste into a client report.

Reads bloodhound-python, SharpHound v3+ and CE output. Uploads go to `lwp-output/_bh_uploads/`, are only ever parsed as JSON, and a failed upload is deleted; the last 10 are kept.

**Scope.** This tab counts and describes. It does not compute attack paths, does not rank objects by exploitability, and does not link findings to attack tooling. For attack path analysis, import the same collection into BloodHound CE.

## Security

This console runs offensive tooling and gives a full shell with the rights of the user who started it.

- It listens on `127.0.0.1` only by default. Keep it that way. To use it from another machine, use an SSH tunnel (`ssh -L 8777:127.0.0.1:8777 kali`) instead of `--host 0.0.0.0`.
- Always keep a token (`run.sh` makes one for you). Every API call and websocket checks it.
- Use it only on engagements where you have written authorization.

## Files

| File | Role |
|---|---|
| `server.py` | Flask backend: PTY manager, websockets, session API, loot browser |
| `menus.json` | Menu tree shown in the sidebar (mirrors `MENUS.md`) |
| `bh_inventory.py` | BloodHound parser + AD hygiene checks (standard library only) |
| `static/` | Dashboard (HTML/CSS/JS) and vendored xterm.js 5.5 (works offline) |
| `run.sh` | Launcher (venv + token) |
| `tests/check_menus.py` | Checks `menus.json` against the script |
| `tests/test_bh_inventory.py` | Tests the hygiene checks on a synthetic collection |
| `Dockerfile.webui` | Image with all linWinPwn tools plus the web UI |

When linWinPwn adds new menu options, add them to `menus.json` (key + label), then run:

```bash
python3 web_ui/tests/check_menus.py
```

It checks every button against the script's menus (reads the script only, runs nothing) and lists options missing from the dashboard.

The BloodHound inventory has its own tests (synthetic collection, no network, no AD):

```bash
python3 web_ui/tests/test_bh_inventory.py
```
