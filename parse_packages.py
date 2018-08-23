#!/usr/bin/env python3

import lzma
import json
import re

key_value_re = re.compile(r"(\S+):\s*(.*)$")


class DebPackage(dict):
    def source(self):
        if('Source' in self):
            return self['Source']
        elif('Package' in self):
            return self['Package']
        else:
            return "UNKNOWN"

def parse_packages_xz(path):
    packages = {}
    with lzma.open(path, "rt") as f:
        package_data = None
        for line in f:
            if(line.strip() == ""):
                if(package_data):
                    if(package_data.source() not in packages):
                        packages[package_data.source()] = []
                    packages[package_data.source()].append(package_data)
                package_data = None
            else:
                dat = key_value_re.match(line)
                if(package_data == None):
                    package_data = DebPackage()
                package_data[dat[1]] = dat[2].strip()

    return packages

if __name__ == "__main__":
    packages = parse_packages_xz("test_data/Packages.xz")
    binary_versions = { k: { p['Package']: p['Version'] for p in v } for k,v in packages.items() }
    print(json.dumps(binary_versions))
