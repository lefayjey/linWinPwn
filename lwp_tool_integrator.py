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

def add_tool_variable(content, tool_name, install_cmd, binary_name, tool_type):
    print(f"{C_BLUE}[*] Adding variable definition for {tool_name}...{C_NC}")
    if f"{tool_name}=" in content:
        return content

    if tool_type == "binary":
        var_line = f"{tool_name}=$(which {binary_name})"
    else:
        var_line = f"{tool_name}=\"$scripts_dir/{binary_name}\""

    # Clean up any extra blank lines before print_banner
    content = re.sub(r"\s+\n(print_banner\(\) \{)", r"\n\1", content)
    return content.replace("print_banner() {", f"{var_line}\n\nprint_banner() {{")


def normalize_auth_placeholder(value):
    # Strip '$' before '{' so both "{user}" and "${user}" are accepted
    normalized = re.sub(r'\$\{', '{', value)

    shell_vars = {
        "user": "${user}",
        "password": "${password}",
        "domain": "${domain}",
        "hash": "${hash}",
        "key": "${aeskey}",
        "cert": "${pfxcert}",
        "krb5cc": "${krb5cc}",
    }
    return normalized.format(**shell_vars)


def insert_line_before_anchor(anchor_pattern, new_line, content, duplicate_check):
    match = re.search(r"^([ \t]*)" + anchor_pattern, content, flags=re.MULTILINE)
    if not match:
        return content
    # Avoid duplicates — look in the 500 chars preceding the anchor
    preceding = content[max(0, match.start() - 500):match.start()]
    if duplicate_check in preceding:
        return content
    indent = match.group(1)
    return content[:match.start()] + indent + new_line + content[match.start():]


def patch_auth_arguments(content, tool_name, auth_mapping):
    print(f"{C_BLUE}[*] Patching authenticate() for {tool_name}...{C_NC}")

    # Regex anchors that locate each authentication method inside authenticate()
    anchors = {
        "null":      r'auth_string=.*?null session.*?\n',
        "user_pass": r'auth_string=.*?password of.*?\n',
        "hash":      r'else\n\s*echo -e "\$\{RED\}\[i\]\$\{NC\} Incorrect format of NTLM hash\.\.\."',
        "kerb":      r'auth_string=.*?Kerberos Ticket of.*?\n',
        "aes":       r'auth_string=.*?AES Kerberos key of.*?\n',
        "cert":      r'auth_string=.*?Certificate of.*?\n',
    }

    for auth_method in ["null", "user_pass", "hash", "kerb", "aes", "cert"]:
        if auth_method in auth_mapping and auth_mapping[auth_method]:
            value = normalize_auth_placeholder(auth_mapping[auth_method])
            # The hash block needs extra indentation (nested inside an if/else)
            extra_indent = "    " if auth_method == "hash" else ""
            new_line = f"{extra_indent}argument_{tool_name}=\"{value}\"\n"
            content = insert_line_before_anchor(
                anchors[auth_method], new_line, content, f"argument_{tool_name}="
            )

    return content

def add_tool_wrapper(content, func_name, var_name, parent_menu, auth_mapping):
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
    
    unsupported_checks, unsupported_names = [], []
    for method, (bool_var, display_name) in auth_info.items():
        if method not in auth_mapping or not auth_mapping[method]:
            unsupported_checks.append(f"[ \"{bool_var}\" == true ]")
            unsupported_names.append(display_name)

    if unsupported_checks:
        action_block = f"    echo -e \"${{BLUE}}[*] Running {func_name}...${{NC}}\"\n    if {' || '.join(unsupported_checks)}; then\n        echo -e \"${{PURPLE}}[-] {func_name} does not support {' or '.join(unsupported_names)} authentication${{NC}}\"\n    else\n        run_command \"${{{var_name}}} ${{argument_{var_name}}}\"\n    fi"
    else:
        action_block = f"    echo -e \"${{BLUE}}[*] Running {func_name}...${{NC}}\"\n    run_command \"${{{var_name}}} ${{argument_{var_name}}}\""

    wrapper_code = f"{func_name}() {{\n    if ! stat \"${{{var_name}}}\" >/dev/null 2>&1; then\n        echo -e \"${{RED}}[-] Please verify the installation of {var_name}${{NC}}\"\n        return\n    fi\n\n{action_block}\n    \n    echo -e \"\"\n}}\n"

    anchor = MENU_ANCHORS.get(parent_menu)
    if anchor and anchor in content:
        anchor_idx = content.find(anchor)
        next_section = re.search(r"\n###### |\n# -+ Menu", content[anchor_idx + len(anchor):])
        insert_idx = anchor_idx + len(anchor) + (next_section.start() if next_section else 0)
        return content[:insert_idx].rstrip() + "\n\n" + wrapper_code + (content[insert_idx:] if next_section else "\n")
    
    for pat in [r"(#\s*-+\s*Menu\s*-+\s*\n)", r"(main_menu\(\)\s*\{)"]:
        match = re.search(pat, content)
        if match: return content[:match.start()] + wrapper_code + "\n" + content[match.start():]
    return content

def patch_menu_entry(content, parent_menu, var_name, option_text, func_name):
    print(f"{C_BLUE}[*] Patching {parent_menu}...{C_NC}")
    menu_pattern = rf"({parent_menu}\(\)\s*\{{.*?)(^[ \t]*)(echo -e \"back\) Go back\")"
    menu_match = re.search(menu_pattern, content, flags=re.DOTALL | re.MULTILINE)
    
    if menu_match:
        existing_options = list(re.finditer(r"check_tool_status \"\$\{.*?\}\" \".*?\" \"(.*?)\"", menu_match.group(1)))
        next_num = str(int(existing_options[-1].group(1)) + 1) if existing_options and existing_options[-1].group(1).isdigit() else (existing_options[-1].group(1) + "+" if existing_options else "1")
        content = content[:menu_match.start(2)] + f"    check_tool_status \"${{{var_name}}}\" \"{option_text}\" \"{next_num}\"\n" + content[menu_match.start(2):]
    else: return content

    case_match = re.search(rf"({parent_menu}\(\)\s*\{{.*?)(^[ \t]*back\))", content, flags=re.DOTALL | re.MULTILINE)
    if case_match: content = content[:case_match.start(2)] + f"    {next_num})\n        {func_name}\n        {parent_menu}\n        ;;\n\n" + content[case_match.start(2):]
    return content

def patch_installer(var_name, cmd, bin_name, tool_type):
    print(f"{C_BLUE}[*] Patching install.sh for {var_name}...{C_NC}")
    if not os.path.exists(INSTALL_PATH): return
    content = read_file(INSTALL_PATH)
    if var_name in content: return

    if "pipx install" in cmd:
        match = re.search(r"pipx install\s+(.*?)(?:\s+--force)?$", cmd)
        if match: cmd = f"pipx_install_or_upgrade {match.group(1).strip()} {bin_name.split('.')[0]}"
    
    def insert_after_last(pattern, line):
        nonlocal content
        matches = list(re.finditer(pattern, content))
        if matches:
            content = content[:matches[-1].end()] + "    " + line + "\n" + content[matches[-1].end():]

    if "pipx" in cmd: insert_after_last(r"(pipx_install_or_upgrade .*?\n)", cmd)
    elif "wget" in cmd: insert_after_last(r"(wget -q .*?\n)", cmd)
            
    if "wget" in cmd:
        match = re.search(r"-O\s+[\"']?(\$scripts_dir/[^\s\"']+)[\"']?", cmd)
        if match:
            dest = match.group(1)
            ext = ".zip" if ".zip" in cmd else (".tar.gz" if ".tar.gz" in cmd else ".tgz" if ".tgz" in cmd else None)
            if ext:
                extract_line = f"unzip -o {dest} -d \"$scripts_dir\"" if ext == ".zip" else f"tar -C $scripts_dir -xf {dest}"
                extract_pattern = r"(unzip -o .*?\n)" if ext == ".zip" else r"(tar -C .*?\n)"
                matches = list(re.finditer(extract_pattern, content))
                if matches: content = content[:matches[-1].end()] + "    " + extract_line + "\n" + content[matches[-1].end():]
                else: 
                    matches = list(re.finditer(r"(chmod \+x .*?\n)", content))
                    if matches: content = content[:matches[0].start()] + "    " + extract_line + "\n\n" + content[matches[0].start():]
            
    if tool_type == "script":
        matches = list(re.finditer(r"(chmod \+x .*?\n)", content))
        if matches: content = content[:matches[-1].end()] + f"    chmod +x \"$scripts_dir/{bin_name}\"\n" + content[matches[-1].end():]

    write_file(INSTALL_PATH, content)

def patch_readme_docs(tool_name, url, parent_menu, option_text, auth_mapping):
    print(f"{C_BLUE}[*] Patching README.md for {tool_name}...{C_NC}")
    if not os.path.exists(README_PATH): return
    content = read_file(README_PATH)
    
    menu_labels = {"ad_menu": "AD Enum menu", "adcs_menu": "ADCS menu", "sccm_menu": "SCCM menu", "gpo_menu": "GPO Menu", "bruteforce_menu": "BruteForce menu", "kerberos_menu": "Kerberos Attacks menu", "shares_menu": "SMB Shares menu", "vulns_menu": "Vuln Checks menu", "mssql_menu": "MSSQL Enumeration menu", "pwd_menu": "Password Dump menu", "modif_menu": "Modification menu", "cmdexec_menu": "Command Execution menu", "netscan_menu": "Network Scan menu"}
    readme_menu = menu_labels.get(parent_menu)
    if readme_menu:
        match = re.search(rf"({readme_menu}\n```\n)(.*?)(\n```)", content, flags=re.DOTALL)
        if match and option_text not in match.group(2):
            lines = match.group(2).strip().split('\n')
            last_match = re.match(r"(\d+|[a-zA-Z]+)\)", lines[-1]) if lines else None
            next_num = str(int(last_match.group(1)) + 1) if last_match and last_match.group(1).isdigit() else (last_match.group(1) + "+" if last_match else "1")
            content = content.replace(match.group(0), match.group(1) + match.group(2).strip() + "\n" + f"{next_num}) {option_text}" + match.group(3))

    if url:
        author_match = re.search(r"github\.com/([^/]+)", url)
        if author_match:
            author = author_match.group(1)
            tools_match = re.search(r"(- Tools:.*?)(\n- References:|\n## )", content, flags=re.DOTALL)
            if tools_match and f" {tool_name}" not in tools_match.group(1):
                lines = tools_match.group(1).splitlines(); found = False
                for i, line in enumerate(lines):
                    if re.match(rf"^(\s*-\s*\[{re.escape(author)}\]\(.*?\) - )(.*?)$", line):
                        lines[i] = re.sub(rf"^(\s*-\s*\[{re.escape(author)}\]\(.*?\) - )(.*?)$", r"\1\2, " + tool_name, line); found = True
                content = content.replace(tools_match.group(1), "\n".join(lines) + "\n") if found else content.replace(tools_match.group(1), tools_match.group(1).rstrip() + f"\n    - [{author}](https://github.com/{author}) - {tool_name}\n")

    auth_table_match = re.search(r"(### Current supported authentications\n\n\|.*?\|\n\|.*?\|\n)(.*?)(\n\n|#|$)", content, flags=re.DOTALL)
    if auth_table_match and f"`{tool_name}`" not in auth_table_match.group(2):
        def auth_icon(key): return "✅" if key in auth_mapping and auth_mapping[key] else "❌"
        pad_cell = lambda text, width: (" " + text).ljust(width)
        cells = [pad_cell(f"`{tool_name}`", 25), pad_cell(auth_icon('null'), 14), pad_cell(auth_icon('user_pass'), 10), pad_cell(auth_icon('hash'), 12), pad_cell(auth_icon('kerb'), 16), pad_cell(auth_icon('aes'), 13), pad_cell(auth_icon('cert'), 13)]
        content = content[:auth_table_match.start()] + auth_table_match.group(1) + auth_table_match.group(2).strip() + "\n" + "|" + "|".join(cells) + "|" + auth_table_match.group(3) + content[auth_table_match.end():]

    write_file(README_PATH, content)

def patch_dep_check(content, var_name, tool_name):
    print(f"{C_BLUE}[*] Patching dependency check for {tool_name}...{C_NC}")

    config_start = content.find("config_menu() {")
    if config_start == -1:
        return content

    pattern = r"(case \$\{option_selected\} in\s+1\))(.*?)(config_menu\s+;;)"
    match = re.search(pattern, content[config_start:], flags=re.DOTALL)
    if not match:
        return content

    abs_start = config_start + match.start()
    abs_end = config_start + match.end()

    header, body, footer = match.groups()
    if f"stat \"${{{var_name}}}\"" in body:
        return content

    check_line = (
        f"        if ! stat \"${{{var_name}}}\" >/dev/null 2>&1; then "
        f"echo -e \"${{RED}}[-] {tool_name} is not installed${{NC}}\"; "
        f"else echo -e \"${{GREEN}}[+] {tool_name} is installed${{NC}}\"; fi"
    )
    new_block = header + body.rstrip() + "\n" + check_line + "\n        " + footer
    return content[:abs_start] + new_block + content[abs_end:]

def main():
    if len(sys.argv) < 2: sys.exit(1)
    config = load_config(sys.argv[1])
    parent_menu = config['menu_info']['parent_menu']
    if parent_menu not in MENU_ANCHORS: print(f"{C_RED}[!] Error: Parent menu '{parent_menu}' not found!{C_NC}"); sys.exit(1)

    content = read_file(LINWINPWN_PATH)
    content = add_tool_variable(content, config['variable_name'], config.get('install_cmd'), config['binary_name'], config.get('type', 'binary'))
    if config.get('auth_mapping'): content = patch_auth_arguments(content, config['variable_name'], config['auth_mapping'])
    content = add_tool_wrapper(content, config['wrapper_function']['name'], config['variable_name'], parent_menu, config.get('auth_mapping', {}))
    content = patch_menu_entry(content, parent_menu, config['variable_name'], config['menu_info']['option_text'], config['wrapper_function']['name'])
    content = patch_dep_check(content, config['variable_name'], config['tool_name'])
    write_file(LINWINPWN_PATH, content)
    
    if 'install_cmd' in config: patch_installer(config['variable_name'], config['install_cmd'], config['binary_name'], config.get('type', 'binary'))
    patch_readme_docs(config['tool_name'], config.get('github_url'), parent_menu, config['menu_info']['option_text'], config.get('auth_mapping', {}))
    print(f"{C_GREEN}[+] Integration complete!{C_NC}")

if __name__ == "__main__": main()
