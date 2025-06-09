#!/usr/bin/env python3

import os
import re

# Directories to search for headers
HEADER_DIRS = [
    "/usr/include/drm",
    "/usr/include/libdrm",
    "/usr/local/include/drm",
    "/usr/include/x86_64-linux-gnu/drm",
]

# Regex to match IOCTL defines
IOCTL_DEFINE_RE = re.compile(r'#define\s+(DRM_IOCTL_[A-Za-z0-9_]+)\s+(.+)')

if __name__ == "__main__":
    found = {}

    for d in HEADER_DIRS:
        if not os.path.isdir(d):
            continue
        for fname in os.listdir(d):
            if not fname.endswith('.h'):
                continue
            path = os.path.join(d, fname)
            with open(path, 'r', errors='ignore') as f:
                for line in f:
                    m = IOCTL_DEFINE_RE.match(line)
                    if m:
                        name, value = m.groups()
                        found[name] = value.strip()

    # Print as C code for easy copy-paste
    for name, value in sorted(found.items()):
        print(f'    printf("{name} 0x%lx\\n", {name});')
