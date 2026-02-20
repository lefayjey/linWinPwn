import json
import re
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LINWINPWN_PATH = os.path.join(SCRIPT_DIR, "./linWinPwn.sh")
INSTALL_PATH = os.path.join(SCRIPT_DIR, "./install.sh")
README_PATH = os.path.join(SCRIPT_DIR, "./README.md")

C_RED, C_GREEN, C_BLUE, C_PURPLE, C_NC = "\033[0;31m", "\033[0;32m", "\033[0;34m", "\033[0;35m", "\033[0m"

MENU_ANCHORS = {
    "ad_menu": "###### ad_enum: AD Enumeration",
    "adcs_menu": "###### adcs_enum: ADCS Enumeration",
    "sccm_menu": "###### sccm: SCCM Enumeration",
    "gpo_menu": "###### gpo_enum: GPO Enumeration",
    "bruteforce_menu": "###### bruteforce: Brute Force attacks",
    "kerberos_menu": "###### kerberos: Kerberos attacks",
    "shares_menu": "###### scan_shares: Shares scan",
    "vulns_menu": "###### vuln_checks: Vulnerability checks",
    "mssql_menu": "###### mssql_checks: MSSQL scan",
    "modif_menu": "###### Modification of AD Objects or Attributes",
    "pwd_menu": "###### pwd_dump: Password Dump",
    "cmdexec_menu": "###### cmd_exec: Open CMD Console",
    "netscan_menu": "###### net_scan: Network Scan"
}

def load_config(path):
    with open(path, 'r') as f: return json.load(f)

def read_file(path):
    with open(path, 'r', encoding='utf-8') as f: return f.read()

def write_file(path, content):
    with open(path, 'w', encoding='utf-8') as f: f.write(content)

def add_variable(content, tool_name, install_cmd, binary_name, tool_type):
    print(f"{C_BLUE}[*] Adding variable definition for {tool_name}...{C_NC}")
    if f"{tool_name}=" in content: return content
    var_line = f"{tool_name}=$(which {binary_name})" if tool_type == "binary" else f"{tool_name}=\"$scripts_dir/{binary_name}\""
    content = re.sub(r"\s+\n(print_banner\(\) \{)", r"\n\1", content)
    return content.replace("print_banner() {", f"{var_line}\n\nprint_banner() {{")

def patch_authenticate(content, tool_name, auth_mapping):
    print(f"{C_BLUE}[*] Patching authenticate() for {tool_name}...{C_NC}")
    def fas(s): return s.format(user="${user}", password="${password}", domain="${domain}", hash="${hash}", key="${aeskey}", cert="${pfxcert}", krb5cc="${krb5cc}")
    def ibp(ap, rep, ct, check_str):
        m = re.search(r"^([ \t]*)" + ap, ct, flags=re.MULTILINE)
        if not m: return ct
        if check_str in ct[max(0, m.start() - 500):m.start()]: return ct
        return ct[:m.start()] + m.group(1) + rep + ct[m.start():]

    anchors = {
        "null": r'auth_string=.*?null session.*?\n',
        "user_pass": r'auth_string=.*?password of.*?\n',
        "hash": r'else\n\s*echo -e "\$\{RED\}\[i\]\$\{NC\} Incorrect format of NTLM hash\.\.\."',
        "kerb": r'auth_string=.*?Kerberos Ticket of.*?\n',
        "aes": r'auth_string=.*?AES Kerberos key of.*?\n',
        "cert": r'auth_string=.*?Certificate of.*?\n'
    }

    for key in ["null", "user_pass", "hash", "kerb", "aes", "cert"]:
        if key in auth_mapping and auth_mapping[key]:
            val = fas(auth_mapping[key])
            prefix = "    " if key == "hash" else ""
            content = ibp(anchors[key], f"{prefix}argument_{tool_name}=\"{val}\"\n", content, f"argument_{tool_name}=")

    return content

def add_wrapper_function(content, func_name, var_name, parent_menu, auth_mapping):
    print(f"{C_BLUE}[*] Adding wrapper {func_name}...{C_NC}")
    if f"{func_name}()" in content: return content

    auth_info = {
        "null": ("${nullsess_bool}", "Null Session"),
        "user_pass": ("${pass_bool}", "Password"),
        "hash": ("${hash_bool}", "NTLM Hash"),
        "kerb": ("${kerb_bool}", "Kerberos"),
        "aes": ("${aeskey_bool}", "AES Key"),
        "cert": ("${cert_bool}", "Certificate")
    }
    
    uv, un = [], []
    for k, (v, n) in auth_info.items():
        if k not in auth_mapping or not auth_mapping[k]:
            uv.append(f"[ \"{v}\" == true ]"); un.append(n)

    if uv:
        ab = f"    echo -e \"${{BLUE}}[*] Running {func_name}...${{NC}}\"\n    if {' || '.join(uv)}; then\n        echo -e \"${{PURPLE}}[-] {func_name} does not support {' or '.join(un)} authentication${{NC}}\"\n    else\n        run_command \"${{{var_name}}} ${{argument_{var_name}}}\"\n    fi"
    else:
        ab = f"    echo -e \"${{BLUE}}[*] Running {func_name}...${{NC}}\"\n    run_command \"${{{var_name}}} ${{argument_{var_name}}}\""

    wc = f"{func_name}() {{\n    if ! stat \"${{{var_name}}}\" >/dev/null 2>&1; then\n        echo -e \"${{RED}}[-] Please verify the installation of {var_name}${{NC}}\"\n        return\n    fi\n\n{ab}\n    \n    echo -e \"\"\n}}\n"

    anc = MENU_ANCHORS.get(parent_menu)
    if anc and anc in content:
        si = content.find(anc)
        ns = re.search(r"\n###### |\n# -+ Menu", content[si + len(anc):])
        idx = si + len(anc) + (ns.start() if ns else 0)
        return content[:idx].rstrip() + "\n\n" + wc + (content[idx:] if ns else "\n")
    
    for pat in [r"(#\s*-+\s*Menu\s*-+\s*\n)", r"(main_menu\(\)\s*\{)"]:
        m = re.search(pat, content)
        if m: return content[:m.start()] + wc + "\n" + content[m.start():]
    return content

def patch_menu(content, parent_menu, var_name, option_text, func_name):
    print(f"{C_BLUE}[*] Patching {parent_menu}...{C_NC}")
    dp = rf"({parent_menu}\(\)\s*\{{.*?)(^[ \t]*)(echo -e \"back\) Go back\")"
    m = re.search(dp, content, flags=re.DOTALL | re.MULTILINE)
    
    if m:
        lms = list(re.finditer(r"check_tool_status \"\$\{.*?\}\" \".*?\" \"(.*?)\"", m.group(1)))
        nn = str(int(lms[-1].group(1)) + 1) if lms and lms[-1].group(1).isdigit() else (lms[-1].group(1) + "+" if lms else "1")
        content = content[:m.start(2)] + f"    check_tool_status \"${{{var_name}}}\" \"{option_text}\" \"{nn}\"\n" + content[m.start(2):]
    else: return content

    cm = re.search(rf"({parent_menu}\(\)\s*\{{.*?)(^[ \t]*back\))", content, flags=re.DOTALL | re.MULTILINE)
    if cm: content = content[:cm.start(2)] + f"    {nn})\n        {func_name}\n        {parent_menu}\n        ;;\n\n" + content[cm.start(2):]
    return content

def patch_install_script(var_name, cmd, bin_name, tool_type):
    print(f"{C_BLUE}[*] Patching install.sh for {var_name}...{C_NC}")
    if not os.path.exists(INSTALL_PATH): return
    content = read_file(INSTALL_PATH)
    if var_name in content: return

    if "pipx install" in cmd:
        m = re.search(r"pipx install\s+(.*?)(?:\s+--force)?$", cmd)
        if m: cmd = f"pipx_install_or_upgrade {m.group(1).strip()} {bin_name.split('.')[0]}"
    
    def ins(p, l): nonlocal content; ms = list(re.finditer(p, content)); content = content[:ms[-1].end()] + "    " + l + "\n" + content[ms[-1].end():] if ms else content

    if "pipx" in cmd: ins(r"(pipx_install_or_upgrade .*?\n)", cmd)
    elif "wget" in cmd: ins(r"(wget -q .*?\n)", cmd)
            
    if "wget" in cmd:
        m = re.search(r"-O\s+[\"']?(\$scripts_dir/[^\s\"']+)[\"']?", cmd)
        if m:
            dest = m.group(1)
            ext = ".zip" if ".zip" in cmd else (".tar.gz" if ".tar.gz" in cmd else ".tgz" if ".tgz" in cmd else None)
            if ext:
                l = f"unzip -o {dest} -d \"$scripts_dir\"" if ext == ".zip" else f"tar -C $scripts_dir -xf {dest}"
                p = r"(unzip -o .*?\n)" if ext == ".zip" else r"(tar -C .*?\n)"
                ms = list(re.finditer(p, content))
                if ms: content = content[:ms[-1].end()] + "    " + l + "\n" + content[ms[-1].end():]
                else: 
                    ms = list(re.finditer(r"(chmod \+x .*?\n)", content))
                    if ms: content = content[:ms[0].start()] + "    " + l + "\n\n" + content[ms[0].start():]
            
    if tool_type == "script":
        ms = list(re.finditer(r"(chmod \+x .*?\n)", content))
        if ms: content = content[:ms[-1].end()] + f"    chmod +x \"$scripts_dir/{bin_name}\"\n" + content[ms[-1].end():]

    write_file(INSTALL_PATH, content)

def patch_readme(tool_name, url, parent, opt, mapping):
    print(f"{C_BLUE}[*] Patching README.md for {tool_name}...{C_NC}")
    if not os.path.exists(README_PATH): return
    content = read_file(README_PATH)
    
    m_map = {"ad_menu": "AD Enum menu", "adcs_menu": "ADCS menu", "sccm_menu": "SCCM menu", "gpo_menu": "GPO Menu", "bruteforce_menu": "BruteForce menu", "kerberos_menu": "Kerberos Attacks menu", "shares_menu": "SMB Shares menu", "vulns_menu": "Vuln Checks menu", "mssql_menu": "MSSQL Enumeration menu", "pwd_menu": "Password Dump menu", "modif_menu": "Modification menu", "cmdexec_menu": "Command Execution menu", "netscan_menu": "Network Scan menu"}
    rm = m_map.get(parent)
    if rm:
        m = re.search(rf"({rm}\n```\n)(.*?)(\n```)", content, flags=re.DOTALL)
        if m and opt not in m.group(2):
            ls = m.group(2).strip().split('\n')
            lm = re.match(r"(\d+|[a-zA-Z]+)\)", ls[-1]) if ls else None
            nxt = str(int(lm.group(1)) + 1) if lm and lm.group(1).isdigit() else (lm.group(1) + "+" if lm else "1")
            content = content.replace(m.group(0), m.group(1) + m.group(2).strip() + "\n" + f"{nxt}) {opt}" + m.group(3))

    if url:
        m = re.search(r"github\.com/([^/]+)", url)
        if m:
            auth = m.group(1)
            mat = re.search(r"(- Tools:.*?)(\n- References:|\n## )", content, flags=re.DOTALL)
            if mat and f" {tool_name}" not in mat.group(1):
                ls = mat.group(1).splitlines(); found = False
                for i, l in enumerate(ls):
                    if re.match(rf"^(\s*-\s*\[{re.escape(auth)}\]\(.*?\) - )(.*?)$", l):
                        ls[i] = re.sub(rf"^(\s*-\s*\[{re.escape(auth)}\]\(.*?\) - )(.*?)$", r"\1\2, " + tool_name, l); found = True
                content = content.replace(mat.group(1), "\n".join(ls) + "\n") if found else content.replace(mat.group(1), mat.group(1).rstrip() + f"\n    - [{auth}](https://github.com/{auth}) - {tool_name}\n")

    m = re.search(r"(### Current supported authentications\n\n\|.*?\|\n\|.*?\|\n)(.*?)(\n\n|#|$)", content, flags=re.DOTALL)
    if m and f"`{tool_name}`" not in m.group(2):
        def gc(k): return "✅" if k in mapping and mapping[k] else "❌"
        pd = lambda t, w: (" " + t).ljust(w)
        cs = [pd(f"`{tool_name}`", 25), pd(gc('null'), 14), pd(gc('user_pass'), 10), pd(gc('hash'), 12), pd(gc('kerb'), 16), pd(gc('aes'), 13), pd(gc('cert'), 13)]
        content = content[:m.start()] + m.group(1) + m.group(2).strip() + "\n" + "|" + "|".join(cs) + "|" + m.group(3) + content[m.end():]

    write_file(README_PATH, content)

def patch_dependency_check(content, var_name, tool_name):
    print(f"{C_BLUE}[*] Patching dependency check for {tool_name}...{C_NC}")
    
    cm_start = content.find("config_menu() {")
    if cm_start == -1: return content
    
    pattern = r"(case \$\{option_selected\} in\s+1\))(.*?)(config_menu\s+;;)"
    match = re.search(pattern, content[cm_start:], flags=re.DOTALL)
    
    if not match: return content
    
    abs_start = cm_start + match.start()
    abs_end = cm_start + match.end()
    
    header, body, footer = match.groups()
    if f"stat \"${{{var_name}}}\"" in body: return content

    check_line = f"        if ! stat \"${{{var_name}}}\" >/dev/null 2>&1; then echo -e \"${{RED}}[-] {tool_name} is not installed${{NC}}\"; else echo -e \"${{GREEN}}[+] {tool_name} is installed${{NC}}\"; fi"
    new_blk = header + body.rstrip() + "\n" + check_line + "\n    " + footer
    return content[:abs_start] + new_blk + content[abs_end:]

def main():
    if len(sys.argv) < 2: sys.exit(1)
    cfg = load_config(sys.argv[1]); pm = cfg['menu_info']['parent_menu']
    if pm not in MENU_ANCHORS: print(f"{C_RED}[!] Error: Parent menu '{pm}' not found!{C_NC}"); sys.exit(1)

    ct = read_file(LINWINPWN_PATH)
    ct = add_variable(ct, cfg['variable_name'], cfg.get('install_cmd'), cfg['binary_name'], cfg.get('type', 'binary'))
    if cfg.get('auth_mapping'): ct = patch_authenticate(ct, cfg['variable_name'], cfg['auth_mapping'])
    ct = add_wrapper_function(ct, cfg['wrapper_function']['name'], cfg['variable_name'], pm, cfg.get('auth_mapping', {}))
    ct = patch_menu(ct, pm, cfg['variable_name'], cfg['menu_info']['option_text'], cfg['wrapper_function']['name'])
    ct = patch_dependency_check(ct, cfg['variable_name'], cfg['tool_name'])
    write_file(LINWINPWN_PATH, ct)
    
    if 'install_cmd' in cfg: patch_install_script(cfg['variable_name'], cfg['install_cmd'], cfg['binary_name'], cfg.get('type', 'binary'))
    patch_readme(cfg['tool_name'], cfg.get('github_url'), pm, cfg['menu_info']['option_text'], cfg.get('auth_mapping', {}))
    print(f"{C_GREEN}[+] Integration complete!{C_NC}")

if __name__ == "__main__": main()
