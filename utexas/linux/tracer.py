#!/usr/bin/env python3

import subprocess
import sys
from colorprint import ColorPrint as cp

FD = -1

def help():
    print("python3 tracer.py <PID>")

def get_str(line):
    global FD

    if b"write(" not in line:
        return None
    first_parenthesis = line.index(b"(")
    first_comma = line.index(b",")
    last_comma = line.rindex(b",")
    fd = int(line[first_parenthesis+1:first_comma])
    if FD == -1 and len(line) <=100:
        FD = fd
    if fd != FD:
        return None
    return line[first_comma+3:last_comma-1]

def snoop(pid: int):
    proc = subprocess.Popen(["strace", "-e", "trace=write", "--attach", str(pid)], stderr=subprocess.PIPE)
    
    line = b""
    for line in iter(proc.stderr.readline, b''):
        if (parsed_line := get_str(line)) != None:
            parsed_line = parsed_line.replace(b"\\177", b"[<-]")
            parsed_line = parsed_line.replace(b"\\33[A", b"[^]")
            parsed_line = parsed_line.replace(b"\\33[B", b"[v]")
            parsed_line = parsed_line.replace(b"\\33[C", b"[>]")
            parsed_line = parsed_line.replace(b"\\33[D", b"[<]")
            parsed_line = parsed_line.replace(b"\\r", b"\n")
            parsed_line = parsed_line.replace(b"\\3", b"[ctrl-c]")
            sys.stdout.buffer.write(parsed_line)
            sys.stdout.flush()

    if proc.returncode != 0:
        cp.print_error(line.decode())
        return

if __name__ == "__main__":
    if len(sys.argv) < 2:
        help()
        sys.exit(1)
    pid = int(sys.argv[1])
    snoop(pid)
