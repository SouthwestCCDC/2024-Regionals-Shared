#!/usr/bin/env python3

import base64
import code
import os
import grp, pwd
import shutil
import subprocess
import sys
from colorprint import ColorPrint as cp
from pick import pick
from pstree import list_processes

LOGGING_IP = "10.10.0.15"
HELPER = "helper"
HISTORY = "/dev/shm/"

def gen_password():
    return base64.b64encode(os.urandom(256)).decode()

def list_users():
    users = []
    for user in pwd.getpwall():
        users.append((user[0], grp.getgrgid(user[3])[0]))
    return users

def change_passwords():
    users = list_users()
    options = [user for user, _ in users]
    title = "Select Users to Change Password"
    while True:
        selected = pick(options, title, multiselect=True, min_selection_count=0)
        if len(selected) > 0:
            invalid = True
            for user in selected:
                print(user[0])
            while invalid:
                resp = input("Are you sure you want to change passwords for the above users? [Y/n/c]: ")
                if resp.lower() == "y":
                    take_backup("/etc/shadow")
                    change_passwd_str = ""
                    for user in selected:
                        password = gen_password()
                        proc = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        stdout, stderr = proc.communicate(input=user[0] + ":" + password)
                        if proc.returncode == 0:
                            change_passwd_str += user[0] + "," + password + "\n"
                        else:
                            cp.print_error(stderr.decode())
                            cp.print_error("could not change password for [" + user[0] + "]")
                    save_file("change_passwd.csv", change_passwd_str[:-1])
                    return
                elif resp.lower() == "n":
                    break
                elif resp.lower() == "c":
                    return
        else:
            break

def dump_iptables():
    result = subprocess.run(["iptables-save"], capture_output=True, text=True)
    
    if result.returncode == 0:
        save_file("iptables", result.stdout)
    else:
        cp.print_error(result.stderr)
        cp.print_error("could not run iptables-save")
    
    result = subprocess.run(["ip6tables-save"], capture_output=True, text=True)
    
    if result.returncode == 0:
        save_file("ip6tables", result.stdout)
    else:
        cp.print_error(result.stderr)
        cp.print_error("could not run ip6tables-save")

def dump_crontab():
    users = list_users()
    crontab_result = ""
    for user in users:
        result = subprocess.run(["crontab", "-u", user[0], "-l"], capture_output=True, text=True)
        if result.returncode == 0:
            crontab_result += "[ " + user[0] + " ]\n" + result.stdout + "\n\n"
    if len(crontab_result) > 0:
        save_file("crontab", crontab_result[:-2])

def dump_interfaces():
    result = subprocess.run(["ip", "a"], capture_output=True, text=True)
    if result.returncode == 0:
        save_file("interfaces", result.stdout)
    else:
        cp.print_error(result.stderr)
        cp.print_error("could not dump interfaces")

def dump_routes():
    result = subprocess.run(["ip", "route", "show", "all"], capture_output=True, text=True)
    if result.returncode == 0:
        save_file("routes", result.stdout)
    else:
        cp.print_error(result.stderr)
        cp.print_error("could not dump routes")

def dump_sessions():
    result = subprocess.run(["w"], capture_output=True, text=True)
    if result.returncode == 0:
        save_file("sessions", result.stdout)
    else:
        print_error(result.stderr)
        print_error("could not dump sessions")

def dump_ports():
    result = subprocess.run(["ss", "-nltup"], capture_output=True, text=True)
    if result.returncode == 0:
        save_file("ports", result.stdout)
    else:
        cp.print_error(result.stderr)
        cp.print_error("could not dump ports")

def dump_authorized_keys():
    users = list_users()
    authorized_keys_result = ""
    for user in users:
        authorized_keys_path = os.path.expanduser("~" + user[0] + "/.ssh/authorized_keys")
        if os.path.exists(authorized_keys_path):
            with open(authorized_keys_path, "r") as file:
                authorized_keys_result += "[ " + user[0] + " ]\n" + file.read() + "\n\n"
    if len(authorized_keys_result) > 0:
        save_file("authorized_keys", authorized_keys_result[:-2])

def dump_processes():
    save_file("processes", list_processes())

def configure_bash():
    if not os.path.exists(HISTORY):
        os.mkdir(HISTORY)
    take_backup("/etc/bash.bashrc")
    with open("/etc/bash.bashrc", "a") as file:
        file.write("\nexport HISTFILE=\"" + HISTORY + ".$USER\"")
        file.write("\nexport HISTTIMEFORMAT=\"%F %T \"\n")
        file.write("\nexport PROMPT_COMMAND=\"history -a;$PROMPT_COMMAND\"")
        result = subprocess.run("shopt -s histappend", shell=True, capture_output=True, text=True, executable="/bin/bash")
        if result.returncode == 0:
            cp.print_pass("setup bash. reload shell for changes to take effect.")
        else:
            cp.print_error(result.stderr)
            cp.print_error("could not configure bash")

        cp.print_pass("bash configured. reload shell for changes to take effect.")

def configure_logging():
    if os.path.exists("/etc/rsyslog.conf"):
        take_backup("/etc/rsyslog.conf")
        with open("/etc/rsyslog.conf", "a") as file:
            file.write(f"*.* @{LOGGING_IP}")
    if os.path.exists("/etc/syslog.conf"):
        take_backup("/etc/syslog.conf")
        with open("/etc/syslog.conf", "a") as file:
            file.write(f"*.* @{LOGGING_IP}")
    if os.path.exists("/etc/environment"):
        take_backup("/etc/environment")
        with open("/etc/environment", "a") as file:
            file.write('PROMPT_COMMAND=\'RETRN_VAL=$?;logger -p local6.debug "exec_command $(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//" )"\'')

def gen_path(basename):
    for root, dirs, files in os.walk(HELPER):
        bkup_num = 0
        for file in files:
            file_hyphen_idx = file.rindex("-")
            if file[:file_hyphen_idx] == basename:
                bkup_num = max(bkup_num, int(file[file_hyphen_idx+1:]))
        bkup_num += 1
    return os.path.join(HELPER, basename + "-" + str(bkup_num))

def save_file(basename, data):
    helper_path = gen_path(basename)
    with open(helper_path, "w") as file:
        file.write(data)

def take_backup(path):
    if not os.path.exists(path):
        cp.print_error("'" + path + "' does not exist")
        return
    basename = os.path.basename(path)
    helper_path = gen_path(basename)
    shutil.copyfile(path, helper_path)

def setup():
    if not os.path.exists(HELPER):
        os.mkdir(HELPER)

if __name__ == "__main__":
    setup()
    if len(sys.argv) >= 2:
        if sys.argv[1] == "sh":
            code.interact(local=locals())
    else:
        pass
        take_backup("/etc/passwd")
        take_backup("/etc/sudoers")
        take_backup("/etc/resolv.conf")
        dump_iptables()
        dump_crontab()
        dump_interfaces()
        dump_routes()
        dump_sessions()
        dump_ports()
        dump_authorized_keys()
        dump_processes()
        change_passwords()
        configure_bash()
        configure_logging()
