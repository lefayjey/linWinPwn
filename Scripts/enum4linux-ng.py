#!/usr/bin/env python3

# pylint: disable=C0301, E1101

### ENUM4LINUX-NG
# This tool is a rewrite of Mark Lowe's (former Portcullis Labs, now Cisco CX Security Labs ) enum4linux.pl,
# a tool for enumerating information from Windows and Samba systems.
# As the original enum4linux.pl, this tool is mainly a wrapper around the Samba tools 'nmblookup', 'net',
# 'rpcclient' and 'smbclient'. Other than the original enum4linux.pl, enum4linux-ng parses all output of
# the previously mentioned commands and (if the user requests so), fills the data in JSON/YAML output.
# The original enum4linux.pl had the additional dependencies 'ldapsearch' and 'polenum.py'. These are
# natively implemented in enum4linux-ng. Console output is colored (can be deactivated by setting the
# environment variable NO_COLOR to an arbitrary value).
#
### CREDITS
# I'd like to thank and give credit to the people at former Portcullis Labs (now Cisco CX Security Labs), namely:
#
# - Mark Lowe for creating the original 'enum4linux.pl'
#   https://github.com/CiscoCXSecurity/enum4linux
#
# - Richard "deanx" Dean for creating the original 'polenum'
#   https://labs.portcullis.co.uk/tools/polenum/
#
# In addition, I'd like to thank and give credit to:
# - Craig "Wh1t3Fox" West for his fork of 'polenum'
#   https://github.com/Wh1t3Fox/polenum
#
#
### DESIGN
#
# Error handling
# ==============
#
# * Functions:
#       * return value is None
#         => an error happened, error messages will be printed out and will end up in the JSON/YAML with value
#            null (see also YAML/JSON below)
#
#       * return value is False for...
#         ...'session_possible'
#         => error, it was not possible to setup a session with the target, therefore any subsequent module runs were
#            omitted
#       * ...'services'-->'accessible'
#         => error, it was not possible to setup a service connection
#         => all other booleans are not errors
#
#       * return value is empty [],{},""
#         => no error, nothing was returned (e.g. a group has no members)
#
# * YAML/JSON:
#       * null
#         => an error happened (see above, a function returned None which translates to null in JSON/YAML) - in
#            this case an error message was generated and can be found under:
#            'errors' -> key for which the error happened (e.g. os_info) -> module name where the error occured
#            (e.g. module_srvinfo)
#
#       * missing key
#         => either it was not part of the enumeration because the user did not request it (aka did not provide
#            the right parameter when running enum4linux-ng)
#         => or it was part of the enumeration but no session could be set up (see above), in this case the
#            'session_possible' should be 'False'
#
### LICENSE
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool. The author accepts no liability
# for damage caused by this tool. If these terms are not acceptable to you, then
# you are not permitted to use this tool.
#
# In all other respects the GPL version 3 applies.
#
# The original enum4linux.pl was released under GPL version 2 or later.
# The original polenum.py was released under GPL version 3.

from argparse import ArgumentParser
from collections import OrderedDict
from datetime import datetime
import json
import os
import random
import re
import shutil
import shlex
import socket
from subprocess import check_output, STDOUT, TimeoutExpired
import sys
import tempfile
from impacket import nmb, smb, smbconnection, smb3
from impacket.smbconnection import SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30
from impacket.dcerpc.v5.rpcrt import DCERPC_v5
from impacket.dcerpc.v5 import transport, samr
from ldap3 import Server, Connection, DSA
import yaml
try:
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import Dumper

###############################################################################
# The following  mappings for nmblookup (nbtstat) status codes to human readable
# format is taken from nbtscan 1.5.1 "statusq.c".  This file in turn
# was derived from the Samba package which contains the following
# license:
#    Unix SMB/Netbios implementation
#    Version 1.9
#    Main SMB server routine
#    Copyright (C) Andrew Tridgell 1992-199
#
#    This program is free software; you can redistribute it and/or modif
#    it under the terms of the GNU General Public License as published b
#    the Free Software Foundation; either version 2 of the License, o
#    (at your option) any later version
#
#    This program is distributed in the hope that it will be useful
#    but WITHOUT ANY WARRANTY; without even the implied warranty o
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See th
#    GNU General Public License for more details
#
#    You should have received a copy of the GNU General Public Licens
#    along with this program; if not, write to the Free Softwar
#    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA
NBT_INFO = [
    ["__MSBROWSE__", "01", False, "Master Browser"],
    ["INet~Services", "1C", False, "IIS"],
    ["IS~", "00", True, "IIS"],
    ["", "00", True, "Workstation Service"],
    ["", "01", True, "Messenger Service"],
    ["", "03", True, "Messenger Service"],
    ["", "06", True, "RAS Server Service"],
    ["", "1F", True, "NetDDE Service"],
    ["", "20", True, "File Server Service"],
    ["", "21", True, "RAS Client Service"],
    ["", "22", True, "Microsoft Exchange Interchange(MSMail Connector)"],
    ["", "23", True, "Microsoft Exchange Store"],
    ["", "24", True, "Microsoft Exchange Directory"],
    ["", "30", True, "Modem Sharing Server Service"],
    ["", "31", True, "Modem Sharing Client Service"],
    ["", "43", True, "SMS Clients Remote Control"],
    ["", "44", True, "SMS Administrators Remote Control Tool"],
    ["", "45", True, "SMS Clients Remote Chat"],
    ["", "46", True, "SMS Clients Remote Transfer"],
    ["", "4C", True, "DEC Pathworks TCPIP service on Windows NT"],
    ["", "52", True, "DEC Pathworks TCPIP service on Windows NT"],
    ["", "87", True, "Microsoft Exchange MTA"],
    ["", "6A", True, "Microsoft Exchange IMC"],
    ["", "BE", True, "Network Monitor Agent"],
    ["", "BF", True, "Network Monitor Application"],
    ["", "03", True, "Messenger Service"],
    ["", "00", False, "Domain/Workgroup Name"],
    ["", "1B", True, "Domain Master Browser"],
    ["", "1C", False, "Domain Controllers"],
    ["", "1D", True, "Master Browser"],
    ["", "1E", False, "Browser Service Elections"],
    ["", "2B", True, "Lotus Notes Server Service"],
    ["IRISMULTICAST", "2F", False, "Lotus Notes"],
    ["IRISNAMESERVER", "33", False, "Lotus Notes"],
    ['Forte_$ND800ZA', "20", True, "DCA IrmaLan Gateway Server Service"]
]

# ACB (Account Control Block) contains flags an SAM account
ACB_DICT = {
        0x00000001: "Account Disabled",
        0x00000200: "Password not expired",
        0x00000400: "Account locked out",
        0x00020000: "Password expired",
        0x00000040: "Interdomain trust account",
        0x00000080: "Workstation trust account",
        0x00000100: "Server trust account",
        0x00002000: "Trusted for delegation"
        }

# Source: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/d275ab19-10b0-40e0-94bb-45b7fc130025
DOMAIN_FIELDS = {
        0x00000001: "DOMAIN_PASSWORD_COMPLEX",
        0x00000002: "DOMAIN_PASSWORD_NO_ANON_CHANGE",
        0x00000004: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE",
        0x00000008: "DOMAIN_PASSWORD_LOCKOUT_ADMINS",
        0x00000010: "DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT",
        0x00000020: "DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE"
        }

# Source: https://docs.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version
OS_VERSIONS = {
        "10.0": "Windows 10, Windows Server 2019, Windows Server 2016",
        "6.3": "Windows 8.1, Windows Server 2012 R2",
        "6.2": "Windows 8, Windows Server 2012",
        "6.1": "Windows 7, Windows Server 2008 R2",
        "6.0": "Windows Vista, Windows Server 2008",
        "5.2": "Windows XP 64-Bit Edition, Windows Server 2003, Windows Server 2003 R2",
        "5.1": "Windows XP",
        "5.0": "Windows 2000",
        }

# Source: https://docs.microsoft.com/de-de/windows/release-health/release-information
OS_RELEASE = {
        "19042": "20H2",
        "19041": "2004",
        "18363": "1909",
        "18362": "1903",
        "17763": "1809",
        "17134": "1803",
        "16299": "1709",
        "15063": "1703",
        "14393": "1607",
        "10586": "1511",
        "10240": "1507"
        }

# Filter for various samba client setup related error messages including bug
# https://bugzilla.samba.org/show_bug.cgi?id=13925
SAMBA_CLIENT_ERRORS = [
        "Unable to initialize messaging context",
        "WARNING: no network interfaces found",
        "Can't load /etc/samba/smb.conf - run testparm to debug it"
    ]

# Translates various SMB dialect values to human readable strings
SMB_DIALECTS = {
        SMB_DIALECT: "SMB 1.0",
        SMB2_DIALECT_002: "SMB 2.02",
        SMB2_DIALECT_21: "SMB 2.1",
        SMB2_DIALECT_30: "SMB 3.0"
    }

# This list will be used by the function nt_status_error_filter() which is typically
# called after running a Samba client command (see run()). The idea is to filter out
# common errors. For very specific status errors, please don't handle them here but
# in the corresponding enumeration class/function.
NT_STATUS_COMMON_ERRORS = [
        "STATUS_ACCOUNT_LOCKED_OUT",
        "STATUS_NO_LOGON_SERVERS",
        "STATUS_ACCESS_DENIED",
        "STATUS_LOGON_FAILURE",
        "STATUS_IO_TIMEOUT",
        "STATUS_NETWORK_UNREACHABLE",
        "STATUS_INVALID_PARAMETER",
        "STATUS_NOT_SUPPORTED",
        # This is a rather strange status which needs more examination and might be
        # removed from here in the future.
        "STATUS_CONNECTION_DISCONNECTED",
        "WERR_ACCESS_DENIED",
        # This error code is from the depths of CIFS/SMBv1
        # https://tools.ietf.org/id/draft-leach-cifs-v1-spec-01.txt
        "ERRSRV:ERRaccess"
    ]

# Mapping from errno to string for socket errors we often come across
SOCKET_ERRORS = {
        11: "timed out",
        110: "timed out",
        111: "connection refused",
        113: "no route to host"
        }

# This is needed for the ServiceScan class
SERVICE_LDAP = "LDAP"
SERVICE_LDAPS = "LDAPS"
SERVICE_SMB = "SMB"
SERVICE_SMB_NETBIOS = "SMB over NetBIOS"
SERVICES = {
        SERVICE_LDAP: 389,
        SERVICE_LDAPS: 636,
        SERVICE_SMB: 445,
        SERVICE_SMB_NETBIOS: 139
        }

# The current list of module names
ENUM_LDAP_DOMAIN_INFO = "enum_ldap_domain_info"
ENUM_NETBIOS = "enum_netbios"
ENUM_SMB = "enum_smb"
ENUM_SESSIONS = "enum_sessions"
ENUM_SMB_DOMAIN_INFO = "enum_smb_domain_info"
ENUM_LSAQUERY_DOMAIN_INFO = "enum_lsaquery_domain_info"
ENUM_USERS_RPC = "enum_users_rpc"
ENUM_GROUPS_RPC = "enum_groups_rpc"
ENUM_SERVICES = "services_check"
ENUM_SHARES = "enum_shares"
ENUM_SERVICES = "enum_services"
ENUM_POLICY = "enum_policy"
ENUM_PRINTERS = "enum_printers"
ENUM_OS_INFO = "enum_os_info"
RID_CYCLING = "rid_cycling"
BRUTE_FORCE_SHARES = "brute_force_shares"

DEPS = ["nmblookup", "net", "rpcclient", "smbclient"]
RID_RANGES = "500-550,1000-1050"
KNOWN_USERNAMES = "administrator,guest,krbtgt,domain admins,root,bin,none"
TIMEOUT = 5

# global_verbose and global_colors should be the only variables which should be written to
global_verbose = False
global_colors = True

class Colors:
    ansi_reset = '\033[0m'
    ansi_red = '\033[91m'
    ansi_green = '\033[92m'
    ansi_yellow = '\033[93m'
    ansi_blue = '\033[94m'

    @classmethod
    def red(cls, msg):
        if global_colors:
            return f"{cls.ansi_red}{msg}{cls.ansi_reset}"
        return msg

    @classmethod
    def green(cls, msg):
        if global_colors:
            return f"{cls.ansi_green}{msg}{cls.ansi_reset}"
        return msg

    @classmethod
    def yellow(cls, msg):
        if global_colors:
            return f"{cls.ansi_yellow}{msg}{cls.ansi_reset}"
        return msg

    @classmethod
    def blue(cls, msg):
        if global_colors:
            return f"{cls.ansi_blue}{msg}{cls.ansi_reset}"
        return msg

class Result:
    '''
    The idea of the Result class is, that functions can easily return a return value
    as well as a return message. The return message can be further processed or printed
    out by the calling function, while the return value is supposed to be added to the
    output dictionary (contained in class Output), which will be later converted to JSON/YAML.
    '''
    def __init__(self, retval, retmsg):
        self.retval = retval
        self.retmsg = retmsg

class Target:
    '''
    Target encapsulates various target information. The class should only be instantiated once and
    passed during the enumeration to the various modules. This allows to modify/update target information
    during enumeration.
    '''
    def __init__(self, host, workgroup, port=None, timeout=None, tls=None, samba_config=None, sessions=False):
        self.host = host
        self.port = port
        self.workgroup = workgroup
        self.timeout = timeout
        self.tls = tls
        self.samba_config = samba_config
        self.sessions = sessions
        self.workgroup_from_long_domain = False
        self.ip_version = None
        self.smb_ports = []
        self.ldap_ports = []
        self.services = []
        self.smb_dialects = []

        if not self.valid_host(host):
            raise Exception()

    def update_workgroup(self, workgroup, long_domain=False):
        # Occassionally lsaquery would return a slightly different domain name than LDAP, e.g.
        # MYDOMAIN vs. MY-DOMAIN. It is unclear what the impact of using one or the other is for
        # subsequent enumeration steps.
        # For now we prefer the domain name from LDAP ("long domain") over the domain/workgroup
        # discovered by lsaquery or others.
        if self.workgroup_from_long_domain:
            return
        if long_domain:
            self.workgroup = workgroup.split('.')[0]
            self.workgroup_from_long_domain = True
        else:
            self.workgroup = workgroup

    def valid_host(self, host):
        try:
            result = socket.getaddrinfo(host, None)
            if result[0][0] == socket.AF_INET6:
                self.ip_version = 6
                return True
            if result[0][0] == socket.AF_INET:
                self.ip_version = 4
                return True
        except:
            pass
        return False

    def as_dict(self):
        return {'target':{'host':self.host, 'workgroup':self.workgroup}}

class Credentials:
    '''
    Stores usernames and password.
    '''
    def __init__(self, user, pw):
        # Create an alternative user with pseudo-random username
        self.random_user = ''.join(random.choice("abcdefghijklmnopqrstuvwxyz") for i in range(8))
        self.user = user
        self.pw = pw

    def as_dict(self):
        return {'credentials':OrderedDict({'user':self.user, 'password':self.pw, 'random_user':self.random_user})}

class SambaConfig:
    '''
    Allows to create custom Samba configurations which can be passed via path to the various Samba client tools.
    Currently such a configuration is always created on tool start. This allows to overcome issues with newer
    releases of the Samba client tools where certain features are disabled by default.
    '''
    def __init__(self, entries):
        config = '\n'.join(['[global]']+entries) + '\n'
        config_file = tempfile.NamedTemporaryFile(delete=False)
        config_file.write(config.encode())
        self.config_filename = config_file.name
        config_file.close()

    def get_path(self):
        return self.config_filename

    def add(self, entries):
        try:
            config = '\n'.join(entries) + '\n'
            config_file = open(self.config_filename, 'a')
            config_file.write(config)
            config_file.close()
            return True
        except:
            return False

    def delete(self):
        try:
            os.remove(self.config_filename)
        except OSError:
            return Result(False, f"Could not delete samba configuration file {self.config_filename}")
        return Result(True, "")

class Output:
    '''
    Output stores the output dictionary which will be filled out during the run of
    the tool. The update() function takes a dictionary, which will then be merged
    into the output dictionary (out_dict). In addition, the update() function is
    responsible for writing the JSON/YAML output.
    '''
    def __init__(self, out_file=None, out_file_type=None):
        self.out_file = out_file
        self.out_file_type = out_file_type
        self.out_dict = OrderedDict({"errors":{}})

    def update(self, content):
        # The following is needed, since python3 does not support nested merge of
        # dictionaries out of the box:

        # Temporarily save the current "errors" sub dict. Then update out_dict with the new
        # content. If "content" also had an "errors" dict (e.g. if the module run failed),
        # this would overwrite the "errors" dict from the previous run. Therefore,
        # we replace the old out_dict["errors"] with the saved one. A proper merge will
        # then be done further down.
        old_errors_dict = self.out_dict["errors"]
        self.out_dict.update(content)
        self.out_dict["errors"] = old_errors_dict

        # Merge dicts
        if "errors" in content:
            new_errors_dict = content["errors"]

            for key, value in new_errors_dict.items():
                if key in old_errors_dict:
                    self.out_dict["errors"][key] = {**old_errors_dict[key], **new_errors_dict[key]}
                else:
                    self.out_dict["errors"][key] = value

    def flush(self):
        # Only for nice JSON/YAML output (errors at the end)
        self.out_dict.move_to_end("errors")

        # Write JSON/YAML
        if self.out_file is not None:
            if "json" in self.out_file_type and not self._write_json():
                return Result(False, f"Could not write JSON output to {self.out_file}.json")
            if "yaml" in self.out_file_type and not self._write_yaml():
                return Result(False, f"Could not write YAML output to {self.out_file}.yaml")
        return Result(True, "")

    def _write_json(self):
        try:
            f = open(f"{self.out_file}.json", 'w')
            f.write(json.dumps(self.out_dict, indent=4))
            f.close()
        except OSError:
            return False
        return True

    def _write_yaml(self):
        try:
            f = open(f"{self.out_file}.yaml", 'w')
            f.write(yamlize(self.out_dict, rstrip=False))
            f.close()
        except OSError:
            return False
        return True

    def as_dict(self):
        return self.out_dict

### Service Scans

class ServiceScan():
    def __init__(self, target, scan_list):
        self.target = target
        self.scan_list = scan_list
        self.services = OrderedDict({})

    def run(self):
        module_name = ENUM_SERVICES
        output = {}

        print_heading(f"Service Scan on {self.target.host}")
        for service, port in SERVICES.items():
            if service not in self.scan_list:
                continue

            print_info(f"Checking {service}")
            result = self.check_accessible(service, port)
            if result.retval:
                print_success(result.retmsg)
            else:
                output = process_error(result.retmsg, ["services"], module_name, output)

            self.services[service] = {"port": port, "accessible": result.retval}

        output["services"] = self.services

        return output

    def check_accessible(self, service, port):
        if self.target.ip_version == 6:
            address_family = socket.AF_INET6
        elif self.target.ip_version == 4:
            address_family = socket.AF_INET

        try:
            sock = socket.socket(address_family, socket.SOCK_STREAM)
            sock.settimeout(self.target.timeout)
            result = sock.connect_ex((self.target.host, port))
            if result == 0:
                return Result(True, f"{service} is accessible on {port}/tcp")
            return Result(False, f"Could not connect to {service} on {port}/tcp: {SOCKET_ERRORS[result]}")
        except Exception:
            return Result(False, f"Could not connect to {service} on {port}/tcp")

    def get_accessible_services(self):
        accessible = []
        for service, entry in self.services.items():
            if entry["accessible"] is True:
                accessible.append(service)
        return accessible

    def get_accessible_ports_by_pattern(self, pattern):
        accessible = []
        for service, entry in self.services.items():
            if pattern in service and entry["accessible"] is True:
                accessible.append(self.services[service]["port"])
        return accessible

### NetBIOS Enumeration

class EnumNetbios():
    def __init__(self, target):
        self.target = target

    def run(self):
        '''
        Run NetBIOS module which collects Netbios names and the workgroup.
        '''
        module_name = ENUM_NETBIOS
        print_heading(f"NetBIOS Names and Workgroup for {self.target.host}")
        output = {"workgroup":None, "nmblookup":None}

        nmblookup = self.nmblookup()
        if nmblookup.retval:
            result = self.get_workgroup(nmblookup.retval)
            if result.retval:
                print_success(result.retmsg)
                output["workgroup"] = result.retval
            else:
                output = process_error(result.retmsg, ["workgroup"], module_name, output)

            result = self.nmblookup_to_human(nmblookup.retval)
            print_success(result.retmsg)
            output["nmblookup"] = result.retval
        else:
            output = process_error(nmblookup.retmsg, ["nmblookup", "workgroup"], module_name, output)

        return output

    def nmblookup(self):
        '''
        Runs nmblookup (a NetBIOS over TCP/IP Client) in order to lookup NetBIOS names information.
        '''
        command = ["nmblookup", "-A", self.target.host]
        result = run(command, "Trying to get NetBIOS names information", timeout=self.target.timeout)

        if not result.retval:
            return Result(None, f"Could not get NetBIOS names information via 'nmblookup': {result.retmsg}")

        if "No reply from" in result.retmsg:
            return Result(None, "Could not get NetBIOS names information via 'nmblookup': host does not reply")

        return Result(result.retmsg, "")

    def get_workgroup(self, nmblookup_result):
        '''
        Extract workgroup from given nmblookoup result.
        '''
        match = re.search(r"^\s+(\S+)\s+<00>\s+-\s+<GROUP>\s+", nmblookup_result, re.MULTILINE)
        if match:
            if valid_workgroup(match.group(1)):
                workgroup = match.group(1)
            else:
                return Result(None, f"Workgroup {workgroup} contains some illegal characters")
        else:
            return Result(None, "Could not find workgroup/domain")
        return Result(workgroup, f"Got domain/workgroup name: {workgroup}")

    def nmblookup_to_human(self, nmblookup_result):
        '''
        Map nmblookup output to human readable strings.
        '''
        output = []
        nmblookup_result = nmblookup_result.splitlines()
        for line in nmblookup_result:
            if "Looking up status of" in line or line == "":
                continue

            line = line.replace("\t", "")
            match = re.match(r"^(\S+)\s+<(..)>\s+-\s+?(<GROUP>)?\s+?[A-Z]", line)
            if match:
                line_val = match.group(1)
                line_code = match.group(2).upper()
                line_group = not match.group(3)
                for entry in NBT_INFO:
                    pattern, code, group, desc = entry
                    if pattern:
                        if pattern in line_val and line_code == code and line_group == group:
                            output.append(line + " " + desc)
                            break
                    else:
                        if line_code == code and line_group == group:
                            output.append(line + " " + desc)
                            break
            else:
                output.append(line)
        return Result(output, f"Full NetBIOS names information:\n{yamlize(output)}")

### SMB checks

class EnumSmb():
    def __init__(self, target, detailed):
        self.target = target
        self.detailed = detailed

    def run(self):
        '''
        Run SMB module which checks whether only SMBv1 is supported.
        '''
        module_name = ENUM_SMB
        print_heading(f"SMB Dialect Check on {self.target.host}")
        output = {}

        for port in self.target.smb_ports:
            print_info(f"Trying on {port}/tcp")
            self.target.port = port
            result = self.check_smb_dialects()
            if result.retval is None:
                output = process_error(result.retmsg, ["smb1_only"], module_name, output)
            else:
                output["smb_dialects"] = result.retval
                print_success(result.retmsg)
                break

        if result.retval:
            self.target.smb_dialects = output["smb_dialects"]

        # Does the target only support SMBv1? Then enforce it!
        if result.retval and result.retval["SMB1 only"]:
            print_info("Enforcing legacy SMBv1 for further enumeration")
            result = self.enforce_smb1()
            if not result.retval:
                output = process_error(result.retmsg, ["smb_dialects"], module_name, output)

        output["smb_dialects"] = result.retval
        return output

    def enforce_smb1(self):
        try:
            if self.target.samba_config.add(['client min protocol = NT1']):
                return Result(True, "")
        except:
            pass
        return Result(False, "Could not enforce SMBv1")

    def check_smb_dialects(self):
        '''
        Current implementations of the samba client tools will enforce at least SMBv2 by default. This will give false
        negatives during session checks, if the target only supports SMBv1. Therefore, we try to find out here whether
        the target system only speaks SMBv1.
        '''
        output = {
                SMB_DIALECTS[SMB_DIALECT]: False,
                SMB_DIALECTS[SMB2_DIALECT_002]: False,
                SMB_DIALECTS[SMB2_DIALECT_21]:False,
                SMB_DIALECTS[SMB2_DIALECT_30]:False,
                "SMB1 only": False,
                "Preferred dialect": None,
                "SMB signing required": None
        }

        smb_dialects = [SMB_DIALECT, SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30]

        # First we let the target decide what dialect it likes to talk.
        current_dialect = None
        try:
            smb_conn = smbconnection.SMBConnection(self.target.host, self.target.host, sess_port=self.target.port, timeout=self.target.timeout)
            current_dialect = smb_conn.getDialect()
            # Check whether SMB signing is required or optional - since this seems to be a global setting, we check it only for the preferred dialect
            output["SMB signing required"] = smb_conn.isSigningRequired()
            smb_conn.close()

            # We found one supported dialect, this is also the dialect the remote host selected/preferred of the offered ones
            output[SMB_DIALECTS[current_dialect]] = True
            output["Preferred dialect"] = SMB_DIALECTS[current_dialect]
        except Exception as exc:
            # Currently the impacket library does not support SMB 3.02 and 3.11. Whenever a remote host only supports 3.02 or 3.11
            # we should end up here. This is somewhat vague, but better when nothing.
            if isinstance(exc, (smb3.SessionError)):
                if nt_status_error_filter(str(exc)) == "STATUS_NOT_SUPPORTED":
                    output["Preferred Dialect"] = "> SMB 3.0"

        # Did the session setup above work? If so, we found a supported SMB dialect and we can remove it from the list,
        # so that we do not run the check twice.
        if current_dialect is not None:
            smb_dialects.remove(current_dialect)
        current_dialect = None

        # Check all remaining dialects (which impacket supports)
        for preferred_dialect in smb_dialects:
            try:
                smb_conn = smbconnection.SMBConnection(self.target.host, self.target.host, sess_port=self.target.port, timeout=self.target.timeout, preferredDialect=preferred_dialect)
                current_dialect = smb_conn.getDialect()
                smb_conn.close()
                if current_dialect == preferred_dialect:
                    output[SMB_DIALECTS[current_dialect]] = True
            except Exception as exc:
                pass

        if output[SMB_DIALECTS[SMB_DIALECT]] and \
                not output[SMB_DIALECTS[SMB2_DIALECT_002]] and \
                not output[SMB_DIALECTS[SMB2_DIALECT_21]] and \
                not output[SMB_DIALECTS[SMB2_DIALECT_30]]:
            output["SMB1 only"] = True

        return Result(output, f"Supported dialects and settings:\n{yamlize(output)}")

### Session Checks

class EnumSessions():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run session check module which tests for user and null sessions.
        '''
        module_name = ENUM_SESSIONS
        print_heading(f"RPC Session Check on {self.target.host}")
        output = {"sessions_possible":False,
                  "null_session_possible":False,
                  "user_session_possible":False,
                  "random_user_session_possible":False}

        # Check null session
        print_info("Check for null session")
        null_session = self.check_user_session(Credentials('', ''))
        if null_session.retval:
            output["null_session_possible"] = True
            print_success(null_session.retmsg)
        else:
            output = process_error(null_session.retmsg, ["null_session_possible"], module_name, output)

        # Check user session
        if self.creds.user:
            print_info("Check for user session")
            user_session = self.check_user_session(self.creds)
            if user_session.retval:
                output["user_session_possible"] = True
                print_success(user_session.retmsg)
            else:
                output = process_error(user_session.retmsg, ["user_session_possible"], module_name, output)

        # Check random user session
        print_info("Check for random user session")
        user_session = self.check_user_session(self.creds, random_user_session=True)
        if user_session.retval:
            output["random_user_session_possible"] = True
            print_success(user_session.retmsg)
            print_hint(f"Rerunning enumeration with user '{self.creds.random_user}' might give more results")
        else:
            output = process_error(user_session.retmsg, ["random_user_session_possible"], module_name, output)

        if output["null_session_possible"] or output["user_session_possible"] or output["random_user_session_possible"]:
            output["sessions_possible"] = True
        else:
            process_error("Sessions failed, neither null nor user sessions were possible", ["sessions_possible", "null_session_possible", "user_session_possible", "random_user_session_possible"], module_name, output)

        return output

    def check_user_session(self, creds, random_user_session=False):
        '''
        Tests access to the IPC$ share.

        General explanation:
        The Common Internet File System(CIFS/Server Message Block (SMB) protocol specifies
        mechanisms for interprocess communication over the network. This is called a named pipe.
        In order to be able to "talk" to these named pipes, a special share named "IPC$" is provided.
        SMB clients can access named pipes by using this share. Older Windows versions supported
        anonymous access to this share (empty username and password), which is called a "null sessions".
        This is a security vulnerability since it allows to gain valuable information about the host
        system.

        How the test works:
        In order to test for a null session, the smbclient command is used, by tring to connect to the
        IPC$ share. If that works, smbclient's 'help' command will be run. If the login was successfull,
        the help command will return a list of possible commands. One of these commands is called
        'case_senstive'. We search for this command as an indicator that the IPC session was setup correctly.
        '''

        if random_user_session:
            user = creds.random_user
            pw = ''
            session_type = "random user"
        elif not creds.user and not creds.pw:
            user = ''
            pw = ''
            session_type = "null"
        else:
            user = creds.user
            pw = creds.pw
            session_type = "user"

        command = ['smbclient', '-t', f"{self.target.timeout}", '-W', self.target.workgroup, f'//{self.target.host}/ipc$', '-U', f'{user}%{pw}', '-c', 'help']
        result = run(command, "Attempting to make session", self.target.samba_config)

        if not result.retval:
            return Result(False, f"Could not establish {session_type} session: {result.retmsg}")

        if "case_sensitive" in result.retmsg:
            return Result(True, f"Server allows session using username '{user}', password '{pw}'")
        return Result(False, f"Could not establish session using '{user}', password '{pw}'")

### Domain Information Enumeration via LDAP

class EnumLdapDomainInfo():
    def __init__(self, target):
        self.target = target

    def run(self):
        '''
        Run ldapsearch module which tries to find out whether host is a parent or
        child DC. Also tries to fetch long domain name. The information are get from
        the LDAP RootDSE.
        '''
        module_name = ENUM_LDAP_DOMAIN_INFO
        print_heading(f"Domain Information via LDAP for {self.target.host}")
        output = {"is_parent_dc":None,
                  "is_child_dc":None,
                  "long_domain":None}

        for with_tls in [False, True]:
            if with_tls:
                if SERVICES[SERVICE_LDAPS] not in self.target.ldap_ports:
                    continue
                print_info(f'Trying LDAPS')
            else:
                if SERVICES[SERVICE_LDAP] not in self.target.ldap_ports:
                    continue
                print_info(f'Trying LDAP')
            self.target.tls = with_tls
            namingcontexts = self.get_namingcontexts()
            if namingcontexts.retval is not None:
                break
            output = process_error(namingcontexts.retmsg, ["is_parent_dc", "is_child_dc", "long_domain"], module_name, output)

        if namingcontexts.retval:
            # Parent/root or child DC?
            result = self.check_parent_dc(namingcontexts.retval)
            if result.retval:
                output["is_parent_dc"] = True
                output["is_child_dc"] = False
            else:
                output["is_parent_dc"] = True
                output["is_child_dc"] = False
            print_success(result.retmsg)

            # Try to get long domain from ldapsearch result
            result = self.get_long_domain(namingcontexts.retval)
            if result.retval:
                print_success(result.retmsg)
                output["long_domain"] = result.retval
            else:
                output = process_error(result.retmsg, ["long_domain"], module_name, output)

        return output

    def get_namingcontexts(self):
        '''
        Tries to connect to LDAP/LDAPS. If successful, it tries to get the naming contexts from
        the so called Root Directory Server Agent Service Entry (RootDSE).
        '''
        try:
            server = Server(self.target.host, use_ssl=self.target.tls, get_info=DSA, connect_timeout=self.target.timeout)
            ldap_con = Connection(server, auto_bind=True)
            ldap_con.unbind()
        except Exception as e:
            if len(e.args) == 1:
                error = str(e.args[0])
            else:
                error = str(e.args[1][0][0])
            if "]" in error:
                error = error.split(']', 1)[1]
            elif ":" in error:
                error = error.split(':', 1)[1]
            error = error.lstrip().rstrip()
            if self.target.tls:
                return Result(None, f"LDAPS connect error: {error}")
            return Result(None, f"LDAP connect error: {error}")

        try:
            if not server.info.naming_contexts:
                return Result([], "NamingContexts are not readable")
        except Exception as e:
            return Result([], "NamingContexts are not readable")

        return Result(server.info.naming_contexts, "")

    def get_long_domain(self, namingcontexts_result):
        '''
        Tries to extract the long domain from the naming contexts.
        '''
        long_domain = ""

        for entry in namingcontexts_result:
            match = re.search("(DC=[^,]+,DC=[^,]+)$", entry)
            if match:
                long_domain = match.group(1)
                long_domain = long_domain.replace("DC=", "")
                long_domain = long_domain.replace(",", ".")
                break
        if long_domain:
            return Result(long_domain, f"Long domain name is: {long_domain}")
        return Result(None, "Could not find long domain")

    def check_parent_dc(self, namingcontexts_result):
        '''
        Checks whether the target is a parent or child domain controller.
        This is done by searching for specific naming contexts.
        '''
        parent = False
        namingcontexts_result = '\n'.join(namingcontexts_result)
        if "DC=DomainDnsZones" in namingcontexts_result or "ForestDnsZones" in namingcontexts_result:
            parent = True
        if parent:
            return Result(True, "Appears to be root/parent DC")
        return Result(False, "Appears to be child DC")

### Domain Information Enumeration via (unauthenticated) SMB

class EnumSmbDomainInfo():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module EnumSmbDomainInfo  which extracts domain information from
        Session Setup Request packets.
        '''
        module_name = ENUM_SMB_DOMAIN_INFO
        print_heading(f"Domain Information via SMB session for {self.target.host}")
        output = {"domain_info":None}

        for port in self.target.smb_ports:
            self.target.port = port
            print_info(f"Enumerating via unauthenticated SMB session on {port}/tcp")
            result_smb = self.enum_from_smb()
            if result_smb.retval:
                print_success(result_smb.retmsg)
                output["domain_info"] = result_smb.retval
                break
            output = process_error(result_smb.retmsg, ["domain_info"], module_name, output)

        return output

    def enum_from_smb(self):
        '''
        Tries to set up an SMB null session. Even if the null session does not succeed, the SMB protocol will transfer
        some information about the remote system in the SMB "Session Setup Response" or the SMB "Session Setup andX Response"
        packet. These are the domain, DNS domain name as well as DNS host name.
        '''
        domain_info = {"NetBIOS computer name":None, "NetBIOS domain name":None, "DNS domain":None, "FQDN":None}

        smb_conn = None
        try:
            smb_conn = smbconnection.SMBConnection(remoteName=self.target.host, remoteHost=self.target.host, sess_port=self.target.port, timeout=self.target.timeout)
            smb_conn.login("", "", "")
        except Exception as e:
            error_msg = process_impacket_smb_exception(e, self.target)
            # STATUS_ACCESS_DENIED is the only error we can safely ignore. It basically tells us that a
            # null session is not allowed, but that is not an issue for our enumeration.
            if not "STATUS_ACCESS_DENIED" in error_msg:
                return Result(None, error_msg)

        # For SMBv1 we can typically find Domain in the "Session Setup AndX Response" packet.
        # For SMBv2 and later we find additional information like the DNS name and the DNS FQDN.
        try:
            domain_info["NetBIOS domain name"] = smb_conn.getServerDomain()
            domain_info["NetBIOS computer name"] = smb_conn.getServerName()
            domain_info["FQDN"] = smb_conn.getServerDNSHostName().rstrip('\x00')
            domain_info["DNS domain"] = smb_conn.getServerDNSDomainName().rstrip('\x00')
        except:
            pass

        if not any(domain_info.values()):
            return Result(None, "Could not enumerate domain information via unauthenticated SMB")
        return Result(domain_info, f"Found domain information via SMB\n{yamlize(domain_info)}")

### Domain Information Enumeration via lsaquery

class EnumLsaqueryDomainInfo():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module lsaquery which tries to get domain information like
        the domain/workgroup name, domain SID and the membership type.
        '''
        module_name = ENUM_LSAQUERY_DOMAIN_INFO
        print_heading(f"Domain Information via RPC for {self.target.host}")
        output = {"workgroup":None,
                  "domain_sid":None,
                  "member_of":None}

        lsaquery = self.lsaquery()
        if lsaquery.retval is not None:
            # Try to get domain/workgroup from lsaquery
            result = self.get_workgroup(lsaquery.retval)
            if result.retval:
                print_success(result.retmsg)
                output["workgroup"] = result.retval
            else:
                output = process_error(result.retmsg, ["workgroup"], module_name, output)

            # Try to get domain SID
            result = self.get_domain_sid(lsaquery.retval)
            if result.retval:
                print_success(result.retmsg)
                output["domain_sid"] = result.retval
            else:
                output = process_error(result.retmsg, ["domain_sid"], module_name, output)

            # Is the host part of a domain or a workgroup?
            result = self.check_is_part_of_workgroup_or_domain(lsaquery.retval)
            if result.retval:
                print_success(result.retmsg)
                output["member_of"] = result.retval
            else:
                output = process_error(result.retmsg, ["member_of"], module_name, output)
        else:
            output = process_error(lsaquery.retmsg, ["workgroup", "domain_sid", "member_of"], module_name, output)

        return output

    def lsaquery(self):
        '''
        Uses the rpcclient command to connect to the named pipe LSARPC (Local Security Authority Remote Procedure Call),
        which allows to do remote management of domain security policies. In this specific case, we use rpcclient's lsaquery
        command. This command will do an LSA_QueryInfoPolicy request to get the domain name and the domain service identifier
        (SID).
        '''
        command = ['rpcclient', '-W', self.target.workgroup, '-U', f'{self.creds.user}%{self.creds.pw}', self.target.host, '-c', 'lsaquery']
        result = run(command, "Attempting to get domain SID", self.target.samba_config, timeout=self.target.timeout)

        if not result.retval:
            return Result(None, f"Could not get domain information via 'lsaquery': {result.retmsg}")

        if result.retval:
            return Result(result.retmsg, "")
        return Result(None, "Could not get information via 'lsaquery'")

    def get_workgroup(self, lsaquery_result):
        '''
        Takes the result of rpclient's lsaquery command and tries to extract the workgroup.
        '''
        workgroup = ""
        if "Domain Name" in lsaquery_result:
            match = re.search("Domain Name: (.*)", lsaquery_result)
            if match:
                #FIXME: Validate domain? --> See valid_workgroup()
                workgroup = match.group(1)

        if workgroup:
            return Result(workgroup, f"Domain: {workgroup}")
        return Result(None, "Could not get workgroup from lsaquery")

    def get_domain_sid(self, lsaquery_result):
        '''
        Takes the result of rpclient's lsaquery command and tries to extract the domain SID.
        '''
        domain_sid = None
        if "Domain Sid: (NULL SID)" in lsaquery_result:
            domain_sid = "NULL SID"
        else:
            match = re.search(r"Domain Sid: (S-\d+-\d+-\d+-\d+-\d+-\d+)", lsaquery_result)
            if match:
                domain_sid = match.group(1)
        if domain_sid:
            return Result(domain_sid, f"SID: {domain_sid}")
        return Result(None, "Could not get domain SID from lsaquery")

    def check_is_part_of_workgroup_or_domain(self, lsaquery_result):
        '''
        Takes the result of rpclient's lsaquery command and tries to determine from the result whether the host
        is part of a domain or workgroup.
        '''
        if "Domain Sid: S-0-0" in lsaquery_result or "Domain Sid: (NULL SID)" in lsaquery_result:
            return Result("workgroup", "Host is part of a workgroup (not a domain)")
        if re.search(r"Domain Sid: S-\d+-\d+-\d+-\d+-\d+-\d+", lsaquery_result):
            return Result("domain", "Host is part of a domain (not a workgroup)")
        return Result(False, "Could not determine if host is part of domain or part of a workgroup")

### OS Information Enumeration

class EnumOsInfo():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module OS info which tries to collect OS information. The module supports both authenticated and unauthenticated
        enumeration. This allows to get some target information without having a working session for many systems.
        '''
        module_name = ENUM_OS_INFO
        print_heading(f"OS Information via RPC for {self.target.host}")
        output = {"os_info":None}
        os_info = {"OS":None, "OS version":None, "OS release": None, "OS build": None, "Native OS":None, "Native LAN manager": None, "Platform id":None, "Server type":None, "Server type string":None}

        # Even an unauthenticated SMB session gives OS information about the target system, collect these first
        for port in self.target.smb_ports:
            self.target.port = port
            print_info(f"Enumerating via unauthenticated SMB session on {port}/tcp")
            result_smb = self.enum_from_smb()
            if result_smb.retval:
                print_success(result_smb.retmsg)
                break
            output = process_error(result_smb.retmsg, ["os_info"], module_name, output)

        if result_smb.retval:
            os_info = {**os_info, **result_smb.retval}

        # If the earlier checks for RPC users sessions succeeded, we can continue by enumerating info via rpcclient's srvinfo
        print_info("Enumerating via 'srvinfo'")
        if self.target.sessions:
            result_srvinfo = self.enum_from_srvinfo()
            if result_srvinfo.retval:
                print_success(result_srvinfo.retmsg)
            else:
                output = process_error(result_srvinfo.retmsg, ["os_info"], module_name, output)

            if result_srvinfo.retval is not None:
                os_info = {**os_info, **result_srvinfo.retval}
        else:
            output = process_error("Skipping 'srvinfo' run, null or user session required", ["os_info"], module_name, output)

        # Take all collected information and generate os_info entry
        if result_smb.retval or (self.target.sessions and result_srvinfo.retval):
            os_info = self.os_info_to_human(os_info)
            print_success(f"After merging OS information we have the following result:\n{yamlize(os_info)}")
            output["os_info"] = os_info

        return output

    def srvinfo(self):
        '''
        Uses rpcclient's srvinfo command to connect to the named pipe SRVSVC in order to call
        NetSrvGetInfo() on the target. This will return OS information (OS version, platform id,
        server type).
        '''

        command = ["rpcclient", "-W", self.target.workgroup, '-U', f'{self.creds.user}%{self.creds.pw}', '-c', 'srvinfo', self.target.host]
        result = run(command, "Attempting to get OS info with command", self.target.samba_config, timeout=self.target.timeout)

        if not result.retval:
            return Result(None, f"Could not get OS info via 'srvinfo': {result.retmsg}")

        # FIXME: Came across this when trying to have multiple RPC sessions open, should this be move to NT_STATUS_COMMON_ERRORS?
        # This error is hard to reproduce.
        if "NT_STATUS_REQUEST_NOT_ACCEPTED" in result.retmsg:
            return Result(None, f"Could not get OS information via srvinfo: STATUS_REQUEST_NOT_ACCEPTED - too many RPC sessions open?")

        return Result(result.retmsg, "")

    def enum_from_srvinfo(self):
        '''
        Parses the output of rpcclient's srvinfo command and extracts the various information.
        '''
        result = self.srvinfo()

        if result.retval is None:
            return result

        os_info = {"OS version":None, "Server type":None, "Server type string":None, "Platform id":None}
        search_patterns = {
                "platform_id":"Platform id",
                "os version":"OS version",
                "server type":"Server type"
                }
        first = True
        for line in result.retval.splitlines():

            if first:
                match = re.search(r"\s+[^\s]+\s+(.*)", line)
                if match:
                    os_info['Server type string'] = match.group(1).rstrip()
                first = False

            for search_pattern in search_patterns.keys():
                match = re.search(fr"\s+{search_pattern}\s+:\s+(.*)", line)
                if match:
                    os_info[search_patterns[search_pattern]] = match.group(1)

        if not os_info:
            return Result(None, "Could not parse result of 'srvinfo' command, please open a GitHub issue")
        return Result(os_info, "Found OS information via 'srvinfo'")

    def enum_from_smb(self):
        '''
        Tries to set up an SMB null session. Even if the null session does not succeed, the SMB protocol will transfer
        some information about the remote system in the SMB "Session Setup Response" or the SMB "Session Setup andX Response"
        packet. This is the major and minor OS version as well as the build number. In SMBv1 also the "Native OS" as well as
        the "Native LAN Manager" will be reported.
        '''
        os_info = {"OS version":None, "OS release":None, "OS build":None, "Native LAN manager":None, "Native OS":None}

        os_major = None
        os_minor = None

        smb1_supported = self.target.smb_dialects[SMB_DIALECTS[SMB_DIALECT]]
        smb1_only = self.target.smb_dialects["SMB1 only"]

        # For SMBv1 we can typically find the "Native OS" (e.g. "Windows 5.1")  and "Native LAN Manager"
        # (e.g. "Windows 2000 LAN Manager") field in the "Session Setup AndX Response" packet.
        # For SMBv2 and later we find the "OS Major" (e.g. 5), "OS Minor" (e.g. 1) as well as the
        # "OS Build" fields in the "SMB2 Session Setup Response packet".

        if smb1_supported:
            smb_conn = None
            try:
                smb_conn = smbconnection.SMBConnection(remoteName=self.target.host, remoteHost=self.target.host, sess_port=self.target.port, timeout=self.target.timeout, preferredDialect=SMB_DIALECT)
                smb_conn.login("", "", "")
            except Exception as e:
                error_msg = process_impacket_smb_exception(e, self.target)
                if not "STATUS_ACCESS_DENIED" in error_msg:
                    return Result(None, error_msg)

            if smb1_only:
                os_info["OS build"] = "not supported"
                os_info["OS release"] = "not supported"

            try:
                native_lanman = smb_conn.getSMBServer().get_server_lanman()
                if native_lanman:
                    os_info["Native LAN manager"] = f"{native_lanman}"

                native_os = smb_conn.getSMBServer().get_server_os()
                if native_os:
                    os_info["Native OS"] = f"{native_os}"
                    match = re.search(r"Windows ([0-9])\.([0-9])", native_os)
                    if match:
                        os_major = match.group(1)
                        os_minor = match.group(2)
            except AttributeError:
                os_info["Native LAN manager"] = "not supported"
                os_info["Native OS"] = "not supported"
            except:
                pass

        if not smb1_only:
            smb_conn = None
            try:
                smb_conn = smbconnection.SMBConnection(remoteName=self.target.host, remoteHost=self.target.host, sess_port=self.target.port, timeout=self.target.timeout)
                smb_conn.login("", "", "")
            except Exception as e:
                error_msg = process_impacket_smb_exception(e, self.target)
                if not "STATUS_ACCESS_DENIED" in error_msg:
                    return Result(None, error_msg)

            if not smb1_supported:
                os_info["Native LAN manager"] = "not supported"
                os_info["Native OS"] = "not supported"

            try:
                os_major = smb_conn.getServerOSMajor()
                os_minor = smb_conn.getServerOSMinor()
            except:
                pass

            try:
                os_build = smb_conn.getServerOSBuild()
                if os_build is not None:
                    os_info["OS build"] = f"{os_build}"
                    if str(os_build) in OS_RELEASE:
                        os_info["OS release"] = OS_RELEASE[f"{os_build}"]
                    else:
                        os_info["OS release"] = ""
                else:
                    os_info["OS build"] = "not supported"
                    os_info["OS release"] = "not supported"
            except:
                pass

        if os_major is not None and os_minor is not None:
            os_info["OS version"] = f"{os_major}.{os_minor}"
        else:
            os_info["OS version"] = "not supported"

        if not any(os_info.values()):
            return Result(None, "Could not enumerate information via unauthenticated SMB")
        return Result(os_info, "Found OS information via SMB")

    def os_info_to_human(self, os_info):
        native_lanman = os_info["Native LAN manager"]
        native_os = os_info["Native OS"]
        version = os_info["OS version"]
        server_type_string = os_info["Server type string"]
        os = "unknown"

        if native_lanman is not None and "Samba" in native_lanman:
            os = f"Linux/Unix ({native_lanman})"
        elif native_os is not None and "Windows" in native_os and not "Windows 5.0" in native_os:
            os = native_os
        elif server_type_string is not None and "Samba" in server_type_string:
            # Examples:
            # Wk Sv ... Samba 4.8.0-Debian
            # Wk Sv ... (Samba 3.0.0)
            match = re.search(r".*(Samba\s.*[^)])", server_type_string)
            if match:
                os = f"Linux/Unix ({match.group(1)})"
            else:
                os = "Linux/Unix"
        elif version in OS_VERSIONS:
            os = OS_VERSIONS[version]

        os_info["OS"] = os

        return os_info


### Users Enumeration via RPC

class EnumUsersRpc():
    def __init__(self, target, creds, detailed):
        self.target = target
        self.creds = creds
        self.detailed = detailed

    def run(self):
        '''
        Run module enum users.
        '''
        module_name = ENUM_USERS_RPC
        print_heading(f"Users via RPC on {self.target.host}")
        output = {}

        # Get user via querydispinfo
        print_info("Enumerating users via 'querydispinfo'")
        users_qdi = self.enum_from_querydispinfo()
        if users_qdi.retval is None:
            output = process_error(users_qdi.retmsg, ["users"], module_name, output)
            users_qdi_output = None
        else:
            print_success(users_qdi.retmsg)
            users_qdi_output = users_qdi.retval

        # Get user via enumdomusers
        print_info("Enumerating users via 'enumdomusers'")
        users_edu = self.enum_from_enumdomusers()
        if users_edu.retval is None:
            output = process_error(users_edu.retmsg, ["users"], module_name, output)
            users_edu_output = None
        else:
            print_success(users_edu.retmsg)
            users_edu_output = users_edu.retval

        # Merge both users dicts
        if users_qdi_output is not None and users_edu_output is not None:
            users = {**users_edu_output, **users_qdi_output}
        elif users_edu_output is None:
            users = users_qdi_output
        else:
            users = users_edu_output

        if users:
            if self.detailed:
                print_info("Enumerating users details")
                for rid in users.keys():
                    name = users[rid]['username']
                    user_details = self.get_details_from_rid(rid, name)
                    if user_details.retval:
                        print_success(user_details.retmsg)
                        users[rid]["details"] = user_details.retval
                    else:
                        output = process_error(user_details.retmsg, ["users"], module_name, output)
                        users[rid]["details"] = ""

            print_success(f"After merging user results we have {len(users.keys())} users total:\n{yamlize(users, sort=True)}")

        output["users"] = users
        return output

    def querydispinfo(self):
        '''
        querydispinfo uses the Security Account Manager Remote Protocol (SAMR) named pipe to run the QueryDisplayInfo() request.
        This request will return users with their corresponding Relative ID (RID) as well as multiple account information like a
        description of the account.
        '''
        command = ['rpcclient', '-W', self.target.workgroup, '-U', f'{self.creds.user}%{self.creds.pw}', '-c', 'querydispinfo', self.target.host]
        result = run(command, "Attempting to get userlist", self.target.samba_config, timeout=self.target.timeout)

        if not result.retval:
            return Result(None, f"Could not find users via 'querydispinfo': {result.retmsg}")

        return Result(result.retmsg, "")

    def enumdomusers(self):
        '''
        enomdomusers command will again use the SAMR named pipe to run the EnumDomainUsers() request. This will again
        return a list of users with their corresponding RID (see querydispinfo()). This is possible since by default
        the registry key HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\RestrictAnonymous = 0. If this is set to
        1 enumeration is no longer possible.
        '''
        command = ["rpcclient", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", "-c", "enumdomusers", self.target.host]
        result = run(command, "Attempting to get userlist", self.target.samba_config, timeout=self.target.timeout)

        if not result.retval:
            return Result(None, f"Could not find users via 'enumdomusers': {result.retmsg}")

        return Result(result.retmsg, "")

    def enum_from_querydispinfo(self):
        '''
        Takes the result of rpclient's querydispinfo and tries to extract the users from it.
        '''
        users = {}
        querydispinfo = self.querydispinfo()

        if querydispinfo.retval is None:
            return querydispinfo

        # Example output of rpcclient's querydispinfo:
        # index: 0x2 RID: 0x3e9 acb: 0x00000010 Account: tester	Name: 	Desc:
        for line in filter(None, querydispinfo.retval.split('\n')):
            match = re.search(r"index:\s+.*\s+RID:\s+(0x[A-F-a-f0-9]+)\s+acb:\s+(.*)\s+Account:\s+(.*)\s+Name:\s+(.*)\s+Desc:\s+(.*)", line)
            if match:
                rid = match.group(1)
                rid = str(int(rid, 16))
                acb = match.group(2)
                username = match.group(3)
                name = match.group(4)
                description = match.group(5)
                users[rid] = OrderedDict({"username":username, "name":name, "acb":acb, "description":description})
            else:
                return Result(None, "Could not extract users from querydispinfo output, please open a GitHub issue")
        return Result(users, f"Found {len(users.keys())} users via 'querydispinfo'")

    def enum_from_enumdomusers(self):
        '''
        Takes the result of rpclient's enumdomusers and tries to extract the users from it.
        '''
        users = {}
        enumdomusers = self.enumdomusers()

        if enumdomusers.retval is None:
            return enumdomusers

        # Example output of rpcclient's enumdomusers:
        # user:[tester] rid:[0x3e9]
        for line in enumdomusers.retval.splitlines():
            match = re.search(r"user:\[(.*)\]\srid:\[(0x[A-F-a-f0-9]+)\]", line)
            if match:
                username = match.group(1)
                rid = match.group(2)
                rid = str(int(rid, 16))
                users[rid] = {"username":username}
            else:
                return Result(None, "Could not extract users from eumdomusers output, please open a GitHub issue")
        return Result(users, f"Found {len(users.keys())} users via 'enumdomusers'")

    def get_details_from_rid(self, rid, name):
        '''
        Takes an RID and makes use of the SAMR named pipe to call QueryUserInfo() on the given RID.
        The output contains lots of information about the corresponding user account.
        '''
        if not valid_rid(rid):
            return Result(None, f"Invalid rid passed: {rid}")

        details = OrderedDict()
        command = ["rpcclient", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", "-c", f"queryuser {rid}", self.target.host]
        result = run(command, "Attempting to get detailed user info", self.target.samba_config, timeout=self.target.timeout)

        if not result.retval:
            return Result(None, f"Could not find details for user '{name}': {result.retmsg}")

        #FIXME: Examine
        if "NT_STATUS_NO_SUCH_USER" in result.retmsg:
            return Result(None, f"Could not find details for user '{name}': STATUS_NO_SUCH_USER")

        match = re.search("([^\n]*User Name.*logon_hrs[^\n]*)", result.retmsg, re.DOTALL)
        if match:
            user_info = match.group(1)
            user_info = user_info.replace("\t", "")

            for line in filter(None, user_info.split('\n')):
                if ':' in line:
                    (key, value) = line.split(":", 1)
                    key = key.rstrip()
                    # Skip user and full name, we have this information already
                    if "User Name" in key or "Full Name" in key:
                        continue
                    details[key] = value
                else:
                    details[line] = ""

            if "acb_info" in details and valid_hex(details["acb_info"]):
                for key in ACB_DICT:
                    if int(details["acb_info"], 16) & key:
                        details[ACB_DICT[key]] = True
                    else:
                        details[ACB_DICT[key]] = False

            return Result(details, f"Found details for user '{name}' (RID {rid})")
        return Result(None, f"Could not find details for user '{name}' (RID {rid})")

### Groups Enumeration via RPC

class EnumGroupsRpc():
    def __init__(self, target, creds, with_members, detailed):
        self.target = target
        self.creds = creds
        self.with_members = with_members
        self.detailed = detailed

    def run(self):
        '''
        Run module enum groups.
        '''
        module_name = ENUM_GROUPS_RPC
        print_heading(f"Groups via RPC on {self.target.host}")
        output = {}
        groups = None

        for grouptype in ["local", "builtin", "domain"]:
            print_info(f"Enumerating {grouptype} groups")
            enum = self.enum(grouptype)
            if enum.retval is None:
                output = process_error(enum.retmsg, ["groups"], module_name, output)
            else:
                if groups is None:
                    groups = {}
                print_success(enum.retmsg)
                groups.update(enum.retval)

        #FIXME: Adjust users enum stuff above so that it looks similar to this one?
        if groups:
            if self.with_members:
                print_info("Enumerating group members")
                for rid in groups.keys():
                    # Get group members
                    groupname = groups[rid]['groupname']
                    grouptype = groups[rid]['type']
                    group_members = self.get_members_from_name(groupname, grouptype, rid)
                    if group_members.retval or group_members.retval == '':
                        print_success(group_members.retmsg)
                    else:
                        output = process_error(group_members.retmsg, ["groups"], module_name, output)
                    groups[rid]["members"] = group_members.retval

            if self.detailed:
                print_info("Enumerating group details")
                for rid in groups.keys():
                    groupname = groups[rid]["groupname"]
                    grouptype = groups[rid]["type"]
                    details = self.get_details_from_rid(rid, groupname, grouptype)

                    if details.retval:
                        print_success(details.retmsg)
                    else:
                        output = process_error(details.retmsg, ["groups"], module_name, output)
                    groups[rid]["details"] = details.retval

            print_success(f"After merging groups results we have {len(groups.keys())} groups total:\n{yamlize(groups, sort=True)}")
        output["groups"] = groups
        return output

    def enum(self, grouptype):
        '''
        Tries to enumerate all groups by calling rpcclient's 'enumalsgroups builtin', 'enumalsgroups domain' as well
        as 'enumdomgroups'.
        '''
        grouptype_dict = {
            "builtin":"enumalsgroups builtin",
            "local":"enumalsgroups domain",
            "domain": "enumdomgroups"
        }

        if grouptype not in ["builtin", "domain", "local"]:
            return Result(None, f"Unsupported grouptype, supported types are: { ','.join(grouptype_dict.keys()) }")

        groups = {}
        enum = self.enum_by_grouptype(grouptype)

        if enum.retval is None:
            return enum

        if not enum.retval:
            return Result({}, f"Found 0 group(s) via '{grouptype_dict[grouptype]}'")

        match = re.search("(group:.*)", enum.retval, re.DOTALL)
        if not match:
            return Result(None, f"Could not parse result of {grouptype_dict[grouptype]} command, please open a GitHub issue")

        # Example output of rpcclient's group commands:
        # group:[RAS and IAS Servers] rid:[0x229]
        for line in enum.retval.splitlines():
            match = re.search(r"group:\[(.*)\]\srid:\[(0x[A-F-a-f0-9]+)\]", line)
            if match:
                groupname = match.group(1)
                rid = match.group(2)
                rid = str(int(rid, 16))
                groups[rid] = OrderedDict({"groupname":groupname, "type":grouptype})
            else:
                return Result(None, f"Could not extract groups from {grouptype_dict[grouptype]} output, please open a GitHub issue")
        return Result(groups, f"Found {len(groups.keys())} groups via '{grouptype_dict[grouptype]}'")

    def enum_by_grouptype(self, grouptype):
        '''
        Tries to fetch groups via rpcclient's enumalsgroups (so called alias groups) and enumdomgroups.
        Grouptype "builtin", "local" and "domain" are supported.
        '''
        grouptype_dict = {
            "builtin":"enumalsgroups builtin",
            "local":"enumalsgroups domain",
            "domain": "enumdomgroups"
        }

        if grouptype not in ["builtin", "domain", "local"]:
            return Result(None, f"Unsupported grouptype, supported types are: { ','.join(grouptype_dict.keys()) }")

        command = ["rpcclient", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", "-c", f"{grouptype_dict[grouptype]}", self.target.host]
        result = run(command, f"Attempting to get {grouptype} groups", self.target.samba_config, timeout=self.target.timeout)

        if not result.retval:
            return Result(None, f"Could not get groups via '{grouptype_dict[grouptype]}': {result.retmsg}")

        return Result(result.retmsg, "")

    def get_members_from_name(self, groupname, grouptype, rid):
        '''
        Takes a group name as first argument and tries to enumerate the group members. This is don by using
        the 'net rpc group members' command.
        '''
        command = ["net", "rpc", "group", "members", groupname, "-t", f"{self.target.timeout}", "-W", self.target.workgroup, "-I", self.target.host, "-U", f"{self.creds.user}%{self.creds.pw}"]
        result = run(command, f"Attempting to get group memberships for {grouptype} group '{groupname}'", self.target.samba_config)

        if not result.retval:
            return Result(None, f"Could not lookup members for {grouptype} group '{groupname}' (RID {rid}): {result.retmsg}")

        members_string = result.retmsg
        members = []
        for member in members_string.splitlines():
            if "Couldn't lookup SIDs" in member:
                return Result(None, f"Could not lookup members for {grouptype} group '{groupname}' (RID {rid}): insufficient user permissions, try a different user")
            if "Couldn't find group" in member:
                return Result(None, f"Could not lookup members for {grouptype} group '{groupname}' (RID {rid}): group not found")
            members.append(member)

        return Result(','.join(members), f"Found {len(members)} member(s) for {grouptype} group '{groupname}' (RID {rid})")

    def get_details_from_rid(self, rid, groupname, grouptype):
        '''
        Takes an RID and makes use of the SAMR named pipe to open the group with OpenGroup() on the given RID.
        '''
        if not valid_rid(rid):
            return Result(None, f"Invalid rid passed: {rid}")

        details = OrderedDict()
        command = ["rpcclient", "-W", self.target.workgroup, "-U", f'{self.creds.user}%{self.creds.pw}', "-c", f"querygroup {rid}", self.target.host]
        result = run(command, "Attempting to get detailed group info", self.target.samba_config, timeout=self.target.timeout)

        if not result.retval:
            return Result(None, f"Could not find details for {grouptype} group '{groupname}': {result.retmsg}")

        #FIXME: Only works for domain groups, otherwise NT_STATUS_NO_SUCH_GROUP is returned
        if "NT_STATUS_NO_SUCH_GROUP" in result.retmsg:
            return Result(None, f"Could not get details for {grouptype} group '{groupname}' (RID {rid}): STATUS_NO_SUCH_GROUP")

        match = re.search("([^\n]*Group Name.*Num Members[^\n]*)", result.retmsg, re.DOTALL)
        if match:
            group_info = match.group(1)
            group_info = group_info.replace("\t", "")

            for line in filter(None, group_info.split('\n')):
                if ':' in line:
                    (key, value) = line.split(":", 1)
                    # Skip group name, we have this information already
                    if "Group Name" in key:
                        continue
                    details[key] = value
                else:
                    details[line] = ""

            return Result(details, f"Found details for {grouptype} group '{groupname}' (RID {rid})")
        return Result(None, f"Could not find details for {grouptype} group '{groupname}' (RID {rid})")

### RID Cycling

class RidCycleParams:
    '''
    Stores the various parameters needed for RID cycling. rid_ranges and known_usernames are mandatory.
    enumerated_input is a dictionary which contains already enumerated input like "users,
    "groups", "machines" and/or a domain sid. By default enumerated_input is an empty dict
    and will be filled up during the tool run.
    '''
    def __init__(self, rid_ranges, known_usernames):
        self.rid_ranges = rid_ranges
        self.known_usernames = known_usernames
        self.enumerated_input = {}

    def set_enumerated_input(self, enum_input):
        for key in ["users", "groups", "machines"]:
            if key in enum_input:
                self.enumerated_input[key] = enum_input[key]
            else:
                self.enumerated_input[key] = None

        if "domain_sid" in enum_input and enum_input["domain_sid"] and "NULL SID" not in enum_input["domain_sid"]:
            self.enumerated_input["domain_sid"] = enum_input["domain_sid"]
        else:
            self.enumerated_input["domain_sid"] = None

class RidCycling():
    def __init__(self, cycle_params, target, creds, detailed):
        self.cycle_params = cycle_params
        self.target = target
        self.creds = creds
        self.detailed = detailed

    def run(self):
        '''
        Run module RID cycling.
        '''
        module_name = RID_CYCLING
        print_heading(f"Users, Groups and Machines on {self.target.host} via RID Cycling")
        output = self.cycle_params.enumerated_input

        # Try to enumerate SIDs first, if we don't have the domain SID already
        if output["domain_sid"]:
            sids_list = [output["domain_sid"]]
        else:
            print_info("Trying to enumerate SIDs")
            sids = self.enum_sids(self.cycle_params.known_usernames)
            if sids.retval is None:
                output = process_error(sids.retmsg, ["users", "groups", "machines"], module_name, output)
                return output
            print_success(sids.retmsg)
            sids_list = sids.retval

        # Keep track of what we found...
        found_count = {"users": 0, "groups": 0, "machines": 0}

        # Run...
        for sid in sids_list:
            print_info(f"Trying SID {sid}")
            rid_cycler = self.rid_cycle(sid, self.cycle_params.rid_ranges)
            for result in rid_cycler:
                # We need the top level key to find out whether we got users, groups, machines or the domain_sid...
                top_level_key = list(result.retval.keys())[0]

                # We found the domain_sid...
                if top_level_key == 'domain_sid':
                    output['domain_sid'] = result.retval['domain_sid']
                    continue

                # ...otherwise "users", "groups" or "machines".
                # Get the RID of what we found (user, group or machine RID) as well as the corresponding entry (dict).
                rid = list(result.retval[top_level_key])[0]
                entry = result.retval[top_level_key][rid]

                # If we have the RID already, we continue...
                if output[top_level_key] is not None and rid in output[top_level_key]:
                    continue

                print_success(result.retmsg)
                found_count[top_level_key] += 1

                # ...else we add the result at the right position.
                if output[top_level_key] is None:
                    output[top_level_key] = {}
                output[top_level_key][rid] = entry

                if self.detailed and ("users" in top_level_key or "groups" in top_level_key):
                    if "users" in top_level_key:
                        rid, entry = list(result.retval["users"].items())[0]
                        name = entry["username"]
                        details = EnumUsersRpc(self.target, self.creds, False).get_details_from_rid(rid, name)
                    elif "groups" in top_level_key:
                        rid, entry = list(result.retval["groups"].items())[0]
                        groupname = entry["groupname"]
                        grouptype = entry["type"]
                        details = EnumGroupsRpc(self.target, self.creds, False, False).get_details_from_rid(rid, groupname, grouptype)

                    if details.retval:
                        print_success(details.retmsg)
                    else:
                        output = process_error(details.retmsg, [top_level_key], module_name, output)
                    output[top_level_key][rid]["details"] = details.retval

        if found_count["users"] == 0 and found_count["groups"] == 0 and found_count["machines"] == 0:
            output = process_error("Could not find any (new) users, (new) groups or (new) machines", ["users", "groups", "machines"], module_name, output)
        else:
            print_success(f"Found {found_count['users']} user(s), {found_count['groups']} group(s), {found_count['machines']} machine(s) in total")

        return output

    def enum_sids(self, users):
        '''
        Tries to enumerate SIDs by looking up user names via rpcclient's lookupnames and by using rpcclient's lsaneumsid.
        '''
        sids = []
        sid_patterns_list = [r"(S-1-5-21-[\d-]+)-\d+", r"(S-1-5-[\d-]+)-\d+", r"(S-1-22-[\d-]+)-\d+"]

        # Try to get a valid SID from well-known user names
        for known_username in users.split(','):
            command = ["rpcclient", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", "-c", f"lookupnames {known_username}", self.target.host]
            result = run(command, f"Attempting to get SID for user {known_username}", self.target.samba_config, error_filter=False, timeout=self.target.timeout)
            sid_string = result.retmsg

            #FIXME: Use nt_status_error_filter - then remove the error_filter=False part above
            if "NT_STATUS_ACCESS_DENIED" in sid_string or "NT_STATUS_NONE_MAPPED" in sid_string:
                continue

            for pattern in sid_patterns_list:
                match = re.search(pattern, sid_string)
                if match:
                    result = match.group(1)
                    if result not in sids:
                        sids.append(result)

        #FIXME: Use nt_status_error_filter - then remove the error_filter=False part above
        # Try to get SID list via lsaenumsid
        command = ["rpcclient", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", "-c", "lsaenumsid", self.target.host]
        result = run(command, "Attempting to get SIDs via 'lsaenumsid'", self.target.samba_config, error_filter=False, timeout=self.target.timeout)

        if "NT_STATUS_ACCESS_DENIED" not in result.retmsg:
            for pattern in sid_patterns_list:
                match_list = re.findall(pattern, result.retmsg)
                for match in match_list:
                    if match not in sids:
                        sids.append(match)

        if sids:
            return Result(sids, f"Found {len(sids)} SID(s)")
        return Result(None, "Could not get any SIDs")

    def rid_cycle(self, sid, rid_ranges):
        '''
        Takes a SID as first parameter well as list of RID ranges (as tuples) as second parameter and does RID cycling.
        '''
        for rid_range in rid_ranges:
            (start_rid, end_rid) = rid_range

            #FIXME: Use nt_status_error_filter - then remove the error_filter=False part above
            for rid in range(start_rid, end_rid+1):
                command = ["rpcclient", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", self.target.host, "-c", f"lookupsids {sid}-{rid}"]
                result = run(command, "RID Cycling", self.target.samba_config, error_filter=False, timeout=self.target.timeout)

                # Example: S-1-5-80-3139157870-2983391045-3678747466-658725712-1004 *unknown*\*unknown* (8)
                match = re.search(r"(S-\d+-\d+-\d+-[\d-]+\s+(.*)\s+[^\)]+\))", result.retmsg)
                if match:
                    sid_and_user = match.group(1)
                    entry = match.group(2)

                    # Samba servers sometimes claim to have user accounts
                    # with the same name as the UID/RID. We don't report these.
                    if re.search(r"-(\d+) .*\\\1 \(", sid_and_user):
                        continue

                    # "(1)" = User, "(2)" = Domain Group,"(3)" = Domain SID,"(4)" = Local Group
                    # "(5)" = Well-known group, "(6)" = Deleted account, "(7)" = Invalid account
                    # "(8)" = Unknown, "(9)" = Machine/Computer account
                    if "(1)" in sid_and_user:
                        yield Result({"users":{str(rid):{"username":entry}}}, f"Found user '{entry}' (RID {rid})")
                    elif "(2)" in sid_and_user:
                        yield Result({"groups":{str(rid):{"groupname":entry, "type":"domain"}}}, f"Found domain group '{entry}' (RID {rid})")
                    elif "(3)" in sid_and_user:
                        yield Result({"domain_sid":f"{sid}-{rid}"}, f"Found domain SID {sid}-{rid}")
                    elif "(4)" in sid_and_user:
                        yield Result({"groups":{str(rid):{"groupname":entry, "type":"builtin"}}}, f"Found builtin group '{entry}' (RID {rid})")
                    elif "(9)" in sid_and_user:
                        yield Result({"machines":{str(rid):{"machine":entry}}}, f"Found machine '{entry}' (RID {rid})")

### Shares Enumeration

class EnumShares():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module enum shares.
        '''
        module_name = ENUM_SHARES
        print_heading(f"Shares via RPC on {self.target.host}")
        output = {}
        shares = None

        enum = self.enum()
        if enum.retval is None:
            output = process_error(enum.retmsg, ["shares"], module_name, output)
        else:
            print_info("Enumerating shares")
            # This will print success even if no shares were found (which is not an error.)
            print_success(enum.retmsg)
            shares = enum.retval
            # Check access if there are any shares.
            if enum.retmsg:
                for share in sorted(shares):
                    print_info(f"Testing share {share}")
                    access = self.check_access(share)
                    if access.retval is None:
                        output = process_error(access.retmsg, ["shares"], module_name, output)
                        continue
                    print_success(access.retmsg)
                    shares[share]['access'] = access.retval

        output["shares"] = shares
        return output

    def enum(self):
        '''
        Tries to enumerate shares with the given username and password. It does this running the smbclient command.
        smbclient will open a connection to the Server Service Remote Protocol named pipe (srvsvc). Once connected
        it calls the NetShareEnumAll() to get a list of shares.
        '''
        command = ["smbclient", "-t", f"{self.target.timeout}", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", "-L", f"//{self.target.host}", "-g"]
        result = run(command, "Attempting to get share list using authentication", self.target.samba_config)

        if not result.retval:
            return Result(None, f"Could not list shares: {result.retmsg}")

        shares = {}
        match_list = re.findall(r"^(Device|Disk|IPC|Printer)\|(.*)\|(.*)$", result.retmsg, re.MULTILINE|re.IGNORECASE)
        if match_list:
            for entry in match_list:
                share_type = entry[0]
                share_name = entry[1]
                share_comment = entry[2].rstrip()
                shares[share_name] = {'type':share_type, 'comment':share_comment}

        if shares:
            return Result(shares, f"Found {len(shares.keys())} share(s):\n{yamlize(shares, sort=True)}")
        return Result(shares, f"Found 0 share(s) for user '{self.creds.user}' with password '{self.creds.pw}', try a different user")

    def check_access(self, share):
        '''
        Takes a share as first argument and checks whether the share is accessible.
        The function returns a dictionary with the keys "mapping" and "listing".
        "mapping" can be either OK or DENIED. OK means the share exists and is accessible.
        "listing" can bei either OK, DENIED, N/A, NOT SUPPORTED or WRONG PASSWORD.
        N/A means directory listing is not allowed, while NOT SUPPORTED means the share does
        not support listing at all. This is the case for shares like IPC$ which is used for
        remote procedure calls.

        In order to enumerate access permissions, smbclient is used with the "dir" command.
        In the background this will send an SMB I/O Control (IOCTL) request in order to list the contents of the share.
        '''
        command = ["smbclient", "-t", f"{self.target.timeout}", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", f"//{self.target.host}/{share}", "-c", "dir"]
        result = run(command, f"Attempting to map share //{self.target.host}/{share}", self.target.samba_config, error_filter=False)

        if "NT_STATUS_BAD_NETWORK_NAME" in result.retmsg:
            return Result(None, "Share doesn't exist")

        if "NT_STATUS_ACCESS_DENIED listing" in result.retmsg:
            return Result({"mapping":"ok", "listing":"denied"}, "Mapping: OK, Listing: DENIED")

        if "NT_STATUS_WRONG_PASSWORD" in result.retmsg:
            return Result({"mapping":"ok", "listing":"wrong password"}, "Mapping: OK, Listing: WRONG PASSWORD")

        if "tree connect failed: NT_STATUS_ACCESS_DENIED" in result.retmsg:
            return Result({"mapping":"denied", "listing":"n/a"}, "Mapping: DENIED, Listing: N/A")

        if "NT_STATUS_INVALID_INFO_CLASS" in result.retmsg\
                or "NT_STATUS_NETWORK_ACCESS_DENIED" in result.retmsg\
                or "NT_STATUS_NOT_A_DIRECTORY" in result.retmsg\
                or "NT_STATUS_NO_SUCH_FILE" in result.retmsg:
            return Result({"mapping":"ok", "listing":"not supported"}, "Mapping: OK, Listing: NOT SUPPORTED")

        if "NT_STATUS_OBJECT_NAME_NOT_FOUND" in result.retmsg:
            return Result(None, "Could not check share: STATUS_OBJECT_NAME_NOT_FOUND")

        if "NT_STATUS_INVALID_PARAMETER" in result.retmsg:
            return Result(None, "Could not check share: STATUS_INVALID_PARAMETER")

        if re.search(r"\n\s+\.\.\s+D.*\d{4}\n", result.retmsg) or re.search(r".*blocks\sof\ssize.*blocks\savailable.*", result.retmsg):
            return Result({"mapping":"ok", "listing":"ok"}, "Mapping: OK, Listing: OK")

        return Result(None, "Could not parse result of smbclient command, please open a GitHub issue")

### Share Brute-Force

class ShareBruteParams:
    '''
    Stores the various parameters needed for Share Bruteforcing. shares_file is mandatory.
    enumerated_input is a dictionary which contains already enumerated shares. By default
    enumerated_input is an empty dict and will be filled up during the tool run.
    '''
    def __init__(self, shares_file):
        self.shares_file = shares_file
        self.enumerated_input = {}

    def set_enumerated_input(self, enum_input):
        if "shares" in enum_input:
            self.enumerated_input["shares"] = enum_input["shares"]
        else:
            self.enumerated_input["shares"] = None

class BruteForceShares():
    def __init__(self, brute_params, target, creds):
        self.brute_params = brute_params
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module bruteforce shares.
        '''
        module_name = BRUTE_FORCE_SHARES
        print_heading(f"Share Bruteforcing on {self.target.host}")
        output = self.brute_params.enumerated_input

        found_count = 0
        try:
            with open(self.brute_params.shares_file) as f:
                for share in f:
                    share = share.rstrip()

                    # Skip all shares we might have found by the enum_shares module already
                    if output["shares"] is not None and share in output["shares"].keys():
                        continue

                    result = EnumShares(self.target, self.creds).check_access(share)
                    if result.retval:
                        if output["shares"] is None:
                            output["shares"] = {}
                        print_success(f"Found share: {share}")
                        print_success(result.retmsg)
                        output["shares"][share] = result.retval
                        found_count += 1
        except:
            output = process_error(f"Failed to open {self.brute_params.shares_file}", ["shares"], module_name, output)

        if found_count == 0:
            output = process_error("Could not find any (new) shares", ["shares"], module_name, output)
        else:
            print_success(f"Found {found_count} (new) share(s) in total")

        return output

### Policy Enumeration

class EnumPolicy():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module enum policy.
        '''
        module_name = ENUM_POLICY
        print_heading(f"Policies via RPC for {self.target.host}")
        output = {}

        for port in self.target.smb_ports:
            print_info(f"Trying port {port}/tcp")
            self.target.port = port
            enum = self.enum()
            if enum.retval is None:
                output = process_error(enum.retmsg, ["policy"], module_name, output)
                output["policy"] = None
            else:
                print_success(enum.retmsg)
                output["policy"] = enum.retval
                break

        return output

    # This function is heavily based on this polenum fork: https://github.com/Wh1t3Fox/polenum
    # The original polenum was written by Richard "deanx" Dean: https://labs.portcullis.co.uk/tools/polenum/
    # All credits to Richard "deanx" Dean and Craig "Wh1t3Fox" West!
    def enum(self):
        '''
        Tries to enum password policy and domain lockout and logoff information by opening a connection to the SAMR
        named pipe and calling SamQueryInformationDomain() as well as SamQueryInformationDomain2().
        '''
        policy = {}

        result = self.samr_init()
        if result.retval[0] is None or result.retval[1] is None:
            return Result(None, result.retmsg)

        dce, domain_handle = result.retval

        # Password policy
        try:
            domain_passwd = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
            result = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_passwd)
            policy["domain_password_information"] = {}
            policy["domain_password_information"]["pw_history_length"] = result['Buffer']['Password']['PasswordHistoryLength'] or "None"
            policy["domain_password_information"]["min_pw_length"] = result['Buffer']['Password']['MinPasswordLength'] or "None"
            policy["domain_password_information"]["min_pw_age"] = self.policy_to_human(int(result['Buffer']['Password']['MinPasswordAge']['LowPart']), int(result['Buffer']['Password']['MinPasswordAge']['HighPart']))
            policy["domain_password_information"]["max_pw_age"] = self.policy_to_human(int(result['Buffer']['Password']['MaxPasswordAge']['LowPart']), int(result['Buffer']['Password']['MaxPasswordAge']['HighPart']))
            policy["domain_password_information"]["pw_properties"] = []
            pw_prop = result['Buffer']['Password']['PasswordProperties']
            for bitmask in DOMAIN_FIELDS:
                if pw_prop & bitmask == bitmask:
                    policy["domain_password_information"]["pw_properties"].append({DOMAIN_FIELDS[bitmask]:True})
                else:
                    policy["domain_password_information"]["pw_properties"].append({DOMAIN_FIELDS[bitmask]:False})
        except Exception as e:
            nt_status_error = nt_status_error_filter(str(e))
            if nt_status_error:
                return Result(None, f"Could not get domain password policy: {nt_status_error}")
            return Result(None, "Could not get domain password policy")

        # Domain lockout
        try:
            domain_lockout = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
            result = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_lockout)
            policy["domain_lockout_information"] = {}
            policy["domain_lockout_information"]["lockout_observation_window"] = self.policy_to_human(0, result['Buffer']['Lockout']['LockoutObservationWindow'], lockout=True)
            policy["domain_lockout_information"]["lockout_duration"] = self.policy_to_human(0, result['Buffer']['Lockout']['LockoutDuration'], lockout=True)
            policy["domain_lockout_information"]["lockout_threshold"] = result['Buffer']['Lockout']['LockoutThreshold'] or "None"
        except Exception as e:
            nt_status_error = nt_status_error_filter(str(e))
            if nt_status_error:
                return Result(None, f"Could not get domain_lockout policy: {nt_status_error}")
            return Result(None, "Could not get domain lockout policy")

        # Domain logoff
        try:
            domain_logoff = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
            result = samr.hSamrQueryInformationDomain2(dce, domainHandle=domain_handle, domainInformationClass=domain_logoff)
            policy["domain_logoff_information"] = {}
            policy["domain_logoff_information"]["force_logoff_time"] = self.policy_to_human(result['Buffer']['Logoff']['ForceLogoff']['LowPart'], result['Buffer']['Logoff']['ForceLogoff']['HighPart'])
        except Exception as e:
            nt_status_error = nt_status_error_filter(str(e))
            if nt_status_error:
                return Result(None, f"Could not get domain_lockout policy: {nt_status_error}")
            return Result(None, "Could not get domain lockout policy")

        return Result(policy, f"Found policy:\n{yamlize(policy)}")

    # This function is heavily based on this polenum fork: https://github.com/Wh1t3Fox/polenum
    # The original polenum was written by Richard "deanx" Dean: https://labs.portcullis.co.uk/tools/polenum/
    # All credits to Richard "deanx" Dean and Craig "Wh1t3Fox" West!
    def samr_init(self):
        '''
        Tries to connect to the SAMR named pipe and get the domain handle.
        '''
        try:
            smb_conn = smbconnection.SMBConnection(remoteName=self.target.host, remoteHost=self.target.host, sess_port=self.target.port, timeout=self.target.timeout)
            smb_conn.login(self.creds.user, self.creds.pw, self.target.workgroup)
            rpctransport = transport.SMBTransport(smb_connection=smb_conn, filename=r'\samr', remoteName=self.target.host)
            dce = DCERPC_v5(rpctransport)
            dce.connect()
            dce.bind(samr.MSRPC_UUID_SAMR)
        except Exception as e:
            return Result((None, None), process_impacket_smb_exception(e, self.target))

        try:
            resp = samr.hSamrConnect2(dce)
        except Exception as e:
            return Result((None, None), process_impacket_smb_exception(e, self.target))

        if resp['ErrorCode'] != 0:
            return Result((None, None), f"SamrConnect2 call failed on port {self.target.port}/tcp")

        resp2 = samr.hSamrEnumerateDomainsInSamServer(dce, serverHandle=resp['ServerHandle'], enumerationContext=0, preferedMaximumLength=500)
        if resp2['ErrorCode'] != 0:
            return Result((None, None), "SamrEnumerateDomainsinSamServer failed")

        resp3 = samr.hSamrLookupDomainInSamServer(dce, serverHandle=resp['ServerHandle'], name=resp2['Buffer']['Buffer'][0]['Name'])
        if resp3['ErrorCode'] != 0:
            return Result((None, None), "SamrLookupDomainInSamServer failed")

        resp4 = samr.hSamrOpenDomain(dce, serverHandle=resp['ServerHandle'], desiredAccess=samr.MAXIMUM_ALLOWED, domainId=resp3['DomainId'])
        if resp4['ErrorCode'] != 0:
            return Result((None, None), "SamrOpenDomain failed")

        #domains = resp2['Buffer']['Buffer']
        domain_handle = resp4['DomainHandle']

        return Result((dce, domain_handle), "")

    # This function is heavily based on this polenum fork: https://github.com/Wh1t3Fox/polenum
    # The original polenum was written by Richard "deanx" Dean: https://labs.portcullis.co.uk/tools/polenum/
    # All credits to Richard "deanx" Dean and Craig "Wh1t3Fox" West!
    def policy_to_human(self, low, high, lockout=False):
        '''
        Converts various values retrieved via the SAMR named pipe into human readable strings.
        '''
        time = ""
        tmp = 0

        if low == 0 and hex(high) == "-0x80000000":
            return "not set"
        if low == 0 and high == 0:
            return "none"

        if not lockout:
            if low != 0:
                high = abs(high+1)
            else:
                high = abs(high)
                low = abs(low)

            tmp = low + (high)*16**8  # convert to 64bit int
            tmp *= (1e-7)  # convert to seconds
        else:
            tmp = abs(high) * (1e-7)

        try:
            minutes = datetime.utcfromtimestamp(tmp).minute
            hours = datetime.utcfromtimestamp(tmp).hour
            time_diff = datetime.utcfromtimestamp(tmp) - datetime.utcfromtimestamp(0)
            days = time_diff.days
        except:
            return "invalid time"

        if days > 1:
            time += f"{days} days "
        elif days == 1:
            time += f"{days} day "
        if hours > 1:
            time += f"{hours} hours "
        elif hours == 1:
            time += f"{hours} hour "
        if minutes > 1:
            time += f"{minutes} minutes"
        elif minutes == 1:
            time += f"{minutes} minute"
        return time

### Printer Enumeration

class EnumPrinters():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module enum printers.
        '''
        module_name = ENUM_PRINTERS
        print_heading(f"Printers via RPC for {self.target.host}")
        output = {}

        enum = self.enum()
        if enum.retval is None:
            output = process_error(enum.retmsg, ["printers"], module_name, output)
            output["printers"] = None
        else:
            print_success(enum.retmsg)
            output["printers"] = enum.retval
        return output

    def enum(self):
        '''
        Tries to enum printer via rpcclient's enumprinters.
        '''
        command = ["rpcclient", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", "-c", "enumprinters", self.target.host]
        result = run(command, "Attempting to get printer info", self.target.samba_config, timeout=self.target.timeout)
        printers = {}

        if not result.retval:
            return Result(None, f"Could not get printer info via 'enumprinters': {result.retmsg}")

        #FIXME: Not 100% about this one, is the spooler propably not running?
        if "NT_STATUS_OBJECT_NAME_NOT_FOUND" in result.retmsg:
            return Result("", "No printers available")
        if "No printers returned." in result.retmsg:
            return Result({}, "No printers returned (this is not an error)")

        nt_status_error = nt_status_error_filter(result.retmsg)
        if nt_status_error:
            return Result(None, f"Could not get printers via 'enumprinters': {nt_status_error}")

        match_list = re.findall(r"\s*flags:\[([^\n]*)\]\n\s*name:\[([^\n]*)\]\n\s*description:\[([^\n]*)\]\n\s*comment:\[([^\n]*)\]", result.retmsg, re.MULTILINE)
        if not match_list:
            return Result(None, "Could not parse result of enumprinters command, please open a GitHub issue")

        for match in match_list:
            flags = match[0]
            name = match[1]
            description = match[2]
            comment = match[3]
            printers[name] = OrderedDict({"description":description, "comment":comment, "flags":flags})

        return Result(printers, f"Found {len(printers.keys())} printer(s):\n{yamlize(printers, sort=True)}")

### Services Enumeration

class EnumServices():
    def __init__(self, target, creds):
        self.target = target
        self.creds = creds

    def run(self):
        '''
        Run module enum services.
        '''
        module_name = ENUM_SERVICES
        print_heading(f"Services via RPC on {self.target.host}")
        output = {'services':None}

        enum = self.enum()
        if enum.retval is None:
            output = process_error(enum.retmsg, ["services"], module_name, output)
        else:
            print_success(enum.retmsg)
            output['services'] = enum.retval

        return output

    def enum(self):
        '''
        Tries to enum services via net rpc serivce list.
        '''
        command = ["net", "rpc", "service", "list", "-t", f"{self.target.timeout}", "-W", self.target.workgroup, "-U", f"{self.creds.user}%{self.creds.pw}", "-I", self.target.host]
        result = run(command, "Attempting to get services", self.target.samba_config)
        services = {}

        if not result.retval:
            return Result(None, f"Could not get services via 'net rpc service list': {result.retmsg}")

        match_list = re.findall(r"([^\s]*)\s*\"(.*)\"", result.retmsg, re.MULTILINE)
        if not match_list:
            return Result(None, "Could not parse result of 'net rpc service list' command, please open a GitHub issue")

        for match in match_list:
            name = match[0]
            description = match[1]
            services[name] = OrderedDict({"description":description})

        return Result(services, f"Found {len(services.keys())} service(s):\n{yamlize(services, True)}")

### Enumerator

class Enumerator():
    def __init__(self, args):

        # Init output files
        if args.out_json_file:
            output = Output(args.out_json_file, "json")
        elif args.out_yaml_file:
            output = Output(args.out_yaml_file, "yaml")
        elif args.out_file:
            output = Output(args.out_file, "json_yaml")
        else:
            output = Output()

        # Init target and creds
        try:
            self.creds = Credentials(args.user, args.pw)
            self.target = Target(args.host, args.workgroup, timeout=args.timeout)
        except:
            raise RuntimeError(f"Target {args.host} is not a valid IP or could not be resolved")

        # Init default SambaConfig, make sure 'client ipc signing' is not required
        try:
            samba_config = SambaConfig(['client ipc signing = auto'])
            self.target.samba_config = samba_config
        except:
            raise RuntimeError("Could not create default samba configuration")

        # Add target host and creds to output, so that it will end up in the JSON/YAML
        output.update(self.target.as_dict())
        output.update(self.creds.as_dict())

        self.args = args
        self.output = output
        self.cycle_params = None
        self.share_brute_params = None

    def run(self):
        # RID Cycling - init parameters
        if self.args.R:
            rid_ranges = self.prepare_rid_ranges()
            self.cycle_params = RidCycleParams(rid_ranges, self.args.users)

        # Shares Brute Force - init parameters
        if self.args.shares_file:
            self.share_brute_params = ShareBruteParams(self.args.shares_file)

        print_heading("Target Information", False)
        print_info(f"Target ........... {self.target.host}")
        print_info(f"Username ......... '{self.creds.user}'")
        print_info(f"Random Username .. '{self.creds.random_user}'")
        print_info(f"Password ......... '{self.creds.pw}'")
        print_info(f"Timeout .......... {self.target.timeout} second(s)")
        if self.args.R:
            print_info(f"RID Range(s) ..... {self.args.ranges}")
            print_info(f"Known Usernames .. '{self.args.users}'")

        # The enumeration starts with a service scan. Currently this scans for
        # SMB and LDAP, simple TCP connect scan is used for that. From the result
        # of the scan and the arguments passed in by the user, a list of modules
        # is generated. These modules will then be run.
        services = self.service_scan()
        self.target.services = services
        modules = self.get_modules(services)
        self.run_modules(modules)

    def service_scan(self):
        # By default we scan for 445/tcp and 139/tcp (SMB).
        # LDAP will be added if the user requested any option which requires LDAP
        # like -L or -A.
        scan_list = [SERVICE_SMB, SERVICE_SMB_NETBIOS]
        if self.args.L:
            scan_list += [SERVICE_LDAP, SERVICE_LDAPS]

        scanner = ServiceScan(self.target, scan_list)
        result = scanner.run()
        self.output.update(result)
        self.target.smb_ports = scanner.get_accessible_ports_by_pattern("SMB")
        self.target.ldap_ports = scanner.get_accessible_ports_by_pattern("LDAP")
        return scanner.get_accessible_services()

    def get_modules(self, services, sessions=True):
        modules = []
        if self.args.N:
            modules.append(ENUM_NETBIOS)

        if SERVICE_LDAP in services or SERVICE_LDAPS in services:
            if self.args.L:
                modules.append(ENUM_LDAP_DOMAIN_INFO)

        if SERVICE_SMB in services or SERVICE_SMB_NETBIOS in services:
            modules.append(ENUM_SMB)
            modules.append(ENUM_SESSIONS)
            modules.append(ENUM_SMB_DOMAIN_INFO)

            # The OS info module supports both session-less (unauthenticated) and session-based (authenticated)
            # enumeration. Therefore, we can run it even if no sessions were possible...
            if self.args.O:
                modules.append(ENUM_OS_INFO)

            # ...the remaining modules still need a working session.
            if sessions:
                modules.append(ENUM_LSAQUERY_DOMAIN_INFO)
                if self.args.U:
                    modules.append(ENUM_USERS_RPC)
                if self.args.G:
                    modules.append(ENUM_GROUPS_RPC)
                if self.args.Gm:
                    modules.append(ENUM_GROUPS_RPC)
                if self.args.R:
                    modules.append(RID_CYCLING)
                if self.args.S:
                    modules.append(ENUM_SHARES)
                if self.args.shares_file:
                    modules.append(BRUTE_FORCE_SHARES)
                if self.args.P:
                    modules.append(ENUM_POLICY)
                if self.args.I:
                    modules.append(ENUM_PRINTERS)
                if self.args.C:
                    modules.append(ENUM_SERVICES)

        return modules

    def run_modules(self, modules):
        # Checks if host is a parent/child domain controller, try to get long domain name
        if ENUM_LDAP_DOMAIN_INFO in modules:
            result = EnumLdapDomainInfo(self.target).run()
            self.output.update(result)
            if not self.target.workgroup and result["long_domain"]:
                self.target.update_workgroup(result["long_domain"], True)

        # Try to retrieve workstation and nbtstat information
        if ENUM_NETBIOS in modules:
            result = EnumNetbios(self.target).run()
            self.output.update(result)
            if not self.target.workgroup and result["workgroup"]:
                self.target.update_workgroup(result["workgroup"])

        # Enumerate supported SMB versions
        if ENUM_SMB in modules:
            result = EnumSmb(self.target, self.args.d).run()
            self.output.update(result)

        # Check for user credential and null sessions
        if ENUM_SESSIONS in modules:
            result = EnumSessions(self.target, self.creds).run()
            self.output.update(result)
            self.target.sessions = self.output.as_dict()['sessions_possible']

        # If sessions are not possible, we regenerate the list of modules again.
        # This will only leave those modules in, which don't require authentication.
        if not self.target.sessions:
            modules = self.get_modules(self.target.services, self.target.sessions)

        # Try to get domain name and sid via lsaquery
        if ENUM_LSAQUERY_DOMAIN_INFO in modules:
            result = EnumLsaqueryDomainInfo(self.target, self.creds).run()
            self.output.update(result)
            if not self.target.workgroup and result["workgroup"]:
                self.target.update_workgroup(result["workgroup"])

        # Try to get domain name and sid via lsaquery
        if ENUM_SMB_DOMAIN_INFO in modules:
            result = EnumSmbDomainInfo(self.target, self.creds).run()
            self.output.update(result)

        # Get OS information like os version, server type string...
        if ENUM_OS_INFO in modules:
            result = EnumOsInfo(self.target, self.creds).run()
            self.output.update(result)

        # Enum users
        if ENUM_USERS_RPC in modules:
            result = EnumUsersRpc(self.target, self.creds, self.args.d).run()
            self.output.update(result)

        # Enum groups
        if ENUM_GROUPS_RPC in modules:
            result = EnumGroupsRpc(self.target, self.creds, self.args.Gm, self.args.d).run()
            self.output.update(result)

        # Enum services
        if ENUM_SERVICES in modules:
            result = EnumServices(self.target, self.creds).run()
            self.output.update(result)

        # Enum shares
        if ENUM_SHARES in modules:
            result = EnumShares(self.target, self.creds).run()
            self.output.update(result)

        # Enum password policy
        if ENUM_POLICY in modules:
            result = EnumPolicy(self.target, self.creds).run()
            self.output.update(result)

        # Enum printers
        if ENUM_PRINTERS in modules:
            result = EnumPrinters(self.target, self.creds).run()
            self.output.update(result)

        # RID Cycling (= bruteforce users, groups and machines)
        if RID_CYCLING in modules:
            self.cycle_params.set_enumerated_input(self.output.as_dict())
            result = RidCycling(self.cycle_params, self.target, self.creds, self.args.d).run()
            self.output.update(result)

        # Brute force shares
        if BRUTE_FORCE_SHARES in modules:
            self.share_brute_params.set_enumerated_input(self.output.as_dict())
            result = BruteForceShares(self.share_brute_params, self.target, self.creds).run()
            self.output.update(result)

        if not self.target.services:
            warn("Aborting remainder of tests since neither SMB nor LDAP are accessible")
        elif not self.target.sessions:
            if SERVICE_SMB not in self.target.services and SERVICE_SMB_NETBIOS not in self.target.services:
                warn("Aborting remainder of tests since SMB is not accessible")
            else:
                warn("Aborting remainder of tests since sessions failed, rerun with valid credentials")

    def prepare_rid_ranges(self):
        '''
        Takes a string containing muliple RID ranges and returns a list of ranges as tuples.
        '''
        rid_ranges = self.args.ranges
        rid_ranges_list = []

        for rid_range in rid_ranges.split(','):
            if rid_range.isdigit():
                start_rid = rid_range
                end_rid = rid_range
            else:
                [start_rid, end_rid] = rid_range.split("-")

            start_rid = int(start_rid)
            end_rid = int(end_rid)

            # Reverse if neccessary
            if start_rid > end_rid:
                start_rid, end_rid = end_rid, start_rid

            rid_ranges_list.append((start_rid, end_rid))

        return rid_ranges_list

    def finish(self):
        errors = []

        # Delete temporary samba config
        if hasattr(self, 'target'):
            if self.target.samba_config is not None and not self.args.keep:
                result = self.target.samba_config.delete()
                if not result.retval:
                    errors.append(result.retmsg)

        # Write YAML/JSON output (if the user requested that)
        if hasattr(self, 'output'):
            result = self.output.flush()
            if not result.retval:
                errors.append(result.retmsg)

        if errors:
            return Result(False, "\n".join(errors))
        return Result(True, "")

###

def run(command, description="", samba_config=None, error_filter=True, timeout=None):
    '''
    Runs a samba client command (net, nmblookup, smbclient or rpcclient) and does some basic output filtering.
    The samba_config parameter allows to pass in a custom samba config, this allows to modify the behaviour of
    the samba client commands during run (e.g. enforce legacy SMBv1).
    '''
    if samba_config:
        command += ["-s", f"{samba_config.get_path()}"]

    if global_verbose and description:
        print_verbose(f"{description}, running command: {' '.join(shlex.quote(x) for x in command)}")

    try:
        output = check_output(command, shell=False, stderr=STDOUT, timeout=timeout)
        retval = 0
    except TimeoutExpired:
        return Result(False, "timed out")
    except Exception as e:
        output = e.output
        retval = 1

    output = output.decode()
    for line in output.splitlines(True):
        if any(entry in line for entry in SAMBA_CLIENT_ERRORS):
            output = output.replace(line, "")
    output = output.rstrip('\n')

    if retval == 1 and not output:
        return Result(False, "empty response")

    if error_filter:
        nt_status_error = nt_status_error_filter(output)
        if nt_status_error:
            return Result(False, nt_status_error)

    return Result(True, output)

### Validation Functions

def valid_timeout(timeout):
    try:
        timeout = int(timeout)
        if timeout >= 0 and timeout <= 600:
            return True
    except ValueError:
        pass
    return False

def valid_rid_ranges(rid_ranges):
    if not rid_ranges:
        return False

    for rid_range in rid_ranges.split(','):
        match = re.search(r"^(\d+)-(\d+)$", rid_range)
        if match:
            continue
        if rid_range.isdigit():
            continue
        return False
    return True

def valid_shares_file(shares_file):
    fault_shares = []
    NL = '\n'

    if not os.path.exists(shares_file):
        return Result(False, f"Shares file {shares_file} does not exist")

    if os.stat(shares_file).st_size == 0:
        return Result(False, f"Shares file {shares_file} is empty")

    try:
        with open(shares_file) as f:
            line_num = 1
            for share in f:
                share = share.rstrip()
                if not valid_share(share):
                    fault_shares.append(f"line {line_num}:{share}")
                line_num += 1
    except:
        return Result(False, f"Could not open shares file {shares_file}")
    if fault_shares:
        return Result(False, f"Shares with illegal characters found in {shares_file}:\n{NL.join(fault_shares)}")
    return Result(True, "")

def valid_share(share):
    if re.search(r"^[a-zA-Z0-9\._\$-]+$", share):
        return True
    return False

def valid_hex(hexnumber):
    if re.search("^0x[0-9a-f]+$", hexnumber.lower()):
        return True
    return False

def valid_rid(rid):
    if isinstance(rid, int) and rid > 0:
        return True
    if rid.isdigit():
        return True
    return False

def valid_workgroup(workgroup):
    if re.match(r"^[A-Za-z0-9_\.-]+$", workgroup):
        return True
    return False

### Print Functions and Error Processing

def print_banner():
    print(f"{Colors.green('ENUM4LINUX - next generation')}\n")

def print_heading(text, leading_newline=True):
    output = f"|    {text}    |"
    length = len(output)

    if leading_newline:
        print()
    print(" " + "="*(length-2))
    print(output)
    print(" " + "="*(length-2))

def print_success(msg):
    print(Colors.green(f"[+] {msg}"))

def print_hint(msg):
    print(Colors.green(f"[H] {msg}"))

def print_error(msg):
    print(Colors.red(f"[-] {msg}"))

def print_info(msg):
    print(Colors.blue(f"[*] {msg}"))

def print_verbose(msg):
    print(f"[V] {msg}")

def process_error(msg, affected_entries, module_name, output_dict):
    '''
    Helper function to print error and update output dictionary at the same time.
    '''
    print_error(msg)

    if not "errors" in output_dict:
        output_dict["errors"] = {}

    for entry in affected_entries:
        if not entry in output_dict["errors"]:
            output_dict["errors"].update({entry: {}})

        if not module_name in output_dict["errors"][entry]:
            output_dict["errors"][entry].update({module_name: []})

        output_dict["errors"][entry][module_name].append(msg)
    return output_dict

def process_impacket_smb_exception(exception, target):
    '''
    Function for handling exceptions during SMB session setup when using the impacket library.
    '''
    if len(exception.args) == 2:
        if isinstance(exception.args[1], ConnectionRefusedError):
            return f"SMB connection error on port {target.port}/tcp: Connection refused"
        if isinstance(exception.args[1], socket.timeout):
            return f"SMB connection error on port {target.port}/tcp: timed out"
    if isinstance(exception, nmb.NetBIOSError):
        return f"SMB connection error on port {target.port}/tcp: session failed"
    if isinstance(exception, (smb.SessionError, smb3.SessionError)):
        nt_status_error = nt_status_error_filter(str(exception))
        if nt_status_error:
            return f"SMB connection error on port {target.port}/tcp: {nt_status_error}"
        return f"SMB connection error on port {target.port}/tcp: session failed"
    if isinstance(exception, AttributeError):
        return f"SMB connection error on port {target.port}/tcp: session failed"
    nt_status_error = nt_status_error_filter(str(exception))
    if nt_status_error:
        return f"SMB connection error on port {target.port}/tcp: {nt_status_error}"
    return f"SMB connection error on port {target.port}/tcp: session failed"

def nt_status_error_filter(msg):
    for error in NT_STATUS_COMMON_ERRORS:
        if error in msg:
            return error
    return ""

def abort(msg):
    '''
    This function is used to abort the tool run on error.
    The given error message will be printed out and the tool will abort with exit code 1.
    '''
    print(Colors.red(f"[!] {msg}"))
    sys.exit(1)

def warn(msg):
    print("\n"+Colors.yellow(f"[!] {msg}"))

def yamlize(msg, sort=False, rstrip=True):
    result = yaml.dump(msg, default_flow_style=False, sort_keys=sort, width=160, Dumper=Dumper)
    if rstrip:
        return result.rstrip()
    return result

### Argument Processing

def check_arguments():
    '''
    Takes all arguments from argv and processes them via ArgumentParser. In addition, some basic
    validation of arguments is done.
    '''

    global global_verbose
    global global_colors

    parser = ArgumentParser(description="""This tool is a rewrite of Mark Lowe's enum4linux.pl, a tool for enumerating information from Windows and Samba systems.
            It is mainly a wrapper around the Samba tools nmblookup, net, rpcclient and smbclient. Other than the original tool it allows to export enumeration results
            as YAML or JSON file, so that it can be further processed with other tools.

            The tool tries to do a 'smart' enumeration. It first checks whether SMB or LDAP is accessible on the target. Depending on the result of this check, it will
            dynamically skip checks (e.g. LDAP checks if LDAP is not running). If SMB is accessible, it will always check whether a session can be set up or not. If no
            session can be set up, the tool will stop enumeration.

            The enumeration process can be interupted with CTRL+C. If the options -oJ or -oY are provided, the tool will write out the current enumeration state to the
            JSON or YAML file, once it receives SIGINT triggered by CTRL+C.

            The tool was made for security professionals and CTF players. Illegal use is prohibited.""")
    parser.add_argument("host")
    parser.add_argument("-A", action="store_true", help="Do all simple enumeration including nmblookup (-U -G -S -P -O -N -I -L). This option is enabled if you don't provide any other option.")
    parser.add_argument("-As", action="store_true", help="Do all simple short enumeration without NetBIOS names lookup (-U -G -S -P -O -I -L)")
    parser.add_argument("-U", action="store_true", help="Get users via RPC")
    parser.add_argument("-G", action="store_true", help="Get groups via RPC")
    parser.add_argument("-Gm", action="store_true", help="Get groups with group members via RPC")
    parser.add_argument("-S", action="store_true", help="Get shares via RPC")
    parser.add_argument("-C", action="store_true", help="Get services via RPC")
    parser.add_argument("-P", action="store_true", help="Get password policy information via RPC")
    parser.add_argument("-O", action="store_true", help="Get OS information via RPC")
    parser.add_argument("-L", action="store_true", help="Get additional domain info via LDAP/LDAPS (for DCs only)")
    parser.add_argument("-I", action="store_true", help="Get printer information via RPC")
    parser.add_argument("-R", action="store_true", help="Enumerate users via RID cycling")
    parser.add_argument("-N", action="store_true", help="Do an NetBIOS names lookup (similar to nbtstat) and try to retrieve workgroup from output")
    parser.add_argument("-w", dest="workgroup", default='', type=str, help="Specify workgroup/domain manually (usually found automatically)")
    parser.add_argument("-u", dest="user", default='', type=str, help="Specify username to use (default \"\")")
    parser.add_argument("-p", dest="pw", default='', type=str, help="Specify password to use (default \"\")")
    parser.add_argument("-d", action="store_true", help="Get detailed information for users and groups, applies to -U, -G and -R")
    parser.add_argument("-k", dest="users", default=KNOWN_USERNAMES, type=str, help=f'User(s) that exists on remote system (default: {KNOWN_USERNAMES}).\nUsed to get sid with "lookupsid known_username"')
    parser.add_argument("-r", dest="ranges", default=RID_RANGES, type=str, help=f"RID ranges to enumerate (default: {RID_RANGES})")
    parser.add_argument("-s", dest="shares_file", help="Brute force guessing for shares")
    parser.add_argument("-t", dest="timeout", default=TIMEOUT, help=f"Sets connection timeout in seconds (default: {TIMEOUT}s)")
    parser.add_argument("-v", dest="verbose", action="store_true", help="Verbose, show full samba tools commands being run (net, rpcclient, etc.)")
    parser.add_argument("--keep", action="store_true", help="Don't delete the Samba configuration file created during tool run after enumeration (useful with -v)")
    out_group = parser.add_mutually_exclusive_group()
    out_group.add_argument("-oJ", dest="out_json_file", help="Writes output to JSON file (extension is added automatically)")
    out_group.add_argument("-oY", dest="out_yaml_file", help="Writes output to YAML file (extension is added automatically)")
    out_group.add_argument("-oA", dest="out_file", help="Writes output to YAML and JSON file (extensions are added automatically)")
    args = parser.parse_args()

    if not (args.A or args.As or args.U or args.G or args.Gm or args.S or args.C or args.P or args.O or args.L or args.I or args.R or args.N or args.shares_file):
        args.A = True

    if args.A or args.As:
        args.G = True
        args.I = True
        args.L = True
        args.O = True
        args.P = True
        args.S = True
        args.U = True

    if args.A:
        args.N = True

    # Only global variable which meant to be modified
    global_verbose = args.verbose

    # Check Workgroup
    if args.workgroup:
        if not valid_workgroup(args.workgroup):
            raise RuntimeError(f"Workgroup '{args.workgroup}' contains illegal character")

    # Check for RID ranges
    if not valid_rid_ranges(args.ranges):
        raise RuntimeError("The given RID ranges should be a range '10-20' or just a single RID like '1199'")

    # Check shares file
    if args.shares_file:
        validation = valid_shares_file(args.shares_file)
        if not validation.retval:
            raise RuntimeError(validation.retmsg)

    # Add given users to list of RID cycle users automatically
    if args.user and args.user not in args.users.split(","):
        args.users += f",{args.user}"

    # Check timeout
    if not valid_timeout(args.timeout):
        raise RuntimeError("Timeout must be a valid integer in the range 0-600")
    args.timeout = int(args.timeout)

    return args

### Dependency Checks

def check_dependencies():
    missing = []

    for dep in DEPS:
        if not shutil.which(dep):
            missing.append(dep)

    if missing:
        error_msg = (f"The following dependend tools are missing: {', '.join(missing)}\n"
                     "     For Gentoo, you need to install the 'samba' package.\n"
                     "     For Debian derivates (like Ubuntu) or ArchLinux, you need to install the 'smbclient' package.\n"
                     "     For Fedora derivates (like RHEL, CentOS), you need to install the 'samba-common-tools' and 'samba-client' package.")
        raise RuntimeError(error_msg)

### Run!

def main():
    # The user can disable colored output via environment variable NO_COLOR (see https://no-color.org)
    global global_colors
    if "NO_COLOR" in os.environ:
        global_colors = False

    print_banner()

    # Check dependencies and process arguments, make sure yaml can handle OrdereDicts
    try:
        Dumper.add_representer(OrderedDict, lambda dumper, data: dumper.represent_mapping('tag:yaml.org,2002:map', data.items()))
        check_dependencies()
        args = check_arguments()
    except Exception as e:
        abort(str(e))

    # Run!
    start_time = datetime.now()
    try:
        enum = Enumerator(args)
        enum.run()
    except RuntimeError as e:
        abort(str(e))
    except KeyboardInterrupt:
        warn("Received SIGINT, aborting enumeration")
    finally:
        if 'enum' in locals():
            result = enum.finish()
            if not result.retval:
                abort(result.retmsg)
    elapsed_time = datetime.now() - start_time

    print(f"\nCompleted after {elapsed_time.total_seconds():.2f} seconds")

if __name__ == "__main__":
    main()
