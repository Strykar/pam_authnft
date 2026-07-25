#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Avinash H. Duduskar
#
# Merge the shared libraries a binary actually links (DT_NEEDED) into a
# syft CycloneDX SBOM. syft scanning a bare ELF records the file itself
# and nothing else, because a stripped .so names no packages; the
# dynamic section does. Each DT_NEEDED soname is resolved to a path via
# ldd, then to its owning distro package and version via dpkg (Debian/
# Ubuntu, the release runner) or pacman (Arch, the dev host). A soname
# that resolves to no package still gets a component, version unknown:
# an incomplete inventory that says so beats a confident empty one.
#
# Usage: sbom-enrich.py <sbom.json> <binary>

import json
import re
import shutil
import subprocess
import sys

def run(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else ''

def dt_needed(binary):
    out = run(['readelf', '-d', binary])
    return re.findall(r'\(NEEDED\)\s+Shared library: \[([^\]]+)\]', out)

def ldd_paths(binary):
    paths = {}
    for line in run(['ldd', binary]).splitlines():
        m = re.match(r'\s*(\S+)\s+=>\s+(\S+)', line)
        if m and m.group(2).startswith('/'):
            paths[m.group(1)] = m.group(2)
    return paths

def owner(path):
    """Return (package, version, purl) or (None, None, None)."""
    if shutil.which('dpkg'):
        out = run(['dpkg', '-S', path])
        if out:
            pkg = out.split(':', 1)[0].strip()
            ver = run(['dpkg-query', '-W', '-f', '${Version}', pkg]).strip()
            if pkg and ver:
                return pkg, ver, f'pkg:deb/ubuntu/{pkg}@{ver}'
    if shutil.which('pacman'):
        out = run(['pacman', '-Qo', path])
        m = re.search(r'is owned by (\S+) (\S+)', out)
        if m:
            return m.group(1), m.group(2), \
                   f'pkg:alpm/arch/{m.group(1)}@{m.group(2)}'
    return None, None, None

def main():
    if len(sys.argv) != 3:
        print(f'usage: {sys.argv[0]} <sbom.json> <binary>', file=sys.stderr)
        return 2
    sbom_path, binary = sys.argv[1], sys.argv[2]
    sbom = json.load(open(sbom_path))

    sonames = dt_needed(binary)
    if not sonames:
        print(f'sbom-enrich: no DT_NEEDED entries found in {binary}',
              file=sys.stderr)
        return 1
    paths = ldd_paths(binary)

    components = sbom.setdefault('components', [])
    present = {c.get('name') for c in components}
    added = 0
    for so in sonames:
        if so in present:
            continue
        pkg = ver = purl = None
        if so in paths:
            pkg, ver, purl = owner(paths[so])
        comp = {
            'type': 'library',
            'bom-ref': f'dt-needed:{so}',
            'name': so,
            'version': ver or 'unknown',
            'description': (f'DT_NEEDED of pam_authnft.so; from {pkg} '
                            f'({paths.get(so, "unresolved path")})'
                            if pkg else
                            f'DT_NEEDED of pam_authnft.so '
                            f'({paths.get(so, "unresolved path")})'),
        }
        if purl:
            comp['purl'] = purl
        components.append(comp)
        added += 1

    json.dump(sbom, open(sbom_path, 'w'), indent=2)
    print(f'sbom-enrich: {added} DT_NEEDED components added '
          f'({len(sonames)} sonames)')
    return 0

if __name__ == '__main__':
    sys.exit(main())
