#!/usr/bin/env python3

import subprocess
import sys
import re

YELLOW = "\033[93m"
CYAN = "\033[96m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


# Replace any sequence of more than 2 spaces with 1/3rd as many (rounded down)
def reduce_spaces(line):

    def replacer(match):
        n = len(match.group(0))
        reduced = n // 3
        return ' ' * reduced if reduced > 0 else '  '

    return re.sub(r' {3,}', replacer, line)


# Use regex to highlight only the exact socket number
def highlight_socket(line, sock):

    return re.sub(rf"({re.escape(sock)})", f"{YELLOW}{BOLD}\\1{RESET}", line)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            f"Usage: {sys.argv[0]} <socket_# 1> <socket_# 2> ... <socket_# n>")
        sys.exit(1)

    sockets = sys.argv[1:]

    for sock in sockets:
        print(f"{CYAN}{BOLD}--- Results for socket {sock} ---{RESET}")
        try:
            result = subprocess.run(["ss", "-a"],
                                    capture_output=True,
                                    text=True,
                                    check=True)
            lines = result.stdout.splitlines()
            matches = [
                highlight_socket(reduce_spaces(line), sock) for line in lines
                if sock in line
            ]
            if matches:
                print("\n".join(matches))
            else:
                print(
                    f"{RED}No results found for socket number {sock}.{RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{RED}Error running 'ss -a': {e}{RESET}")
