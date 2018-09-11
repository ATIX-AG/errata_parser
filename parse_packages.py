#!/usr/bin/env python3

import lzma
import debian.debian_support as debs
import json
import sys

def parse_packages_fileobj(f, name):
    packages = {}
    for p in debs.PackageFile(name, file_obj=f):
        temp = dict(p)
        source = temp['Source'] if 'Source' in temp else temp['Package']
        if(source not in packages):
            packages[source] = []
        packages[source].append(temp)
    return packages

def parse_packages_xz(path):
    with lzma.open(path, "rt") as f:
        return parse_packages_fileobj(f, path)

def parse_packages(path):
    with open(path, "r") as f:
        return parse_packages_fileobj(f, path)


if __name__ == "__main__":
    package_file = [
            "test_data/Packages.xz",
            "test_data/Packages_all"
            ]
    binary_versions = {}
    if(len(sys.argv) > 1):
        package_file = sys.argv.copy
        package_file.remove(0)
    for p in package_file:
        if(p.endswith('.xz')):
            packages = parse_packages_xz(p)
        else:
            packages = parse_packages(p)

        for k, v in packages.items():
            pkgs = { p['Package']: p['Version'] for p in v }
            if(k in binary_versions):
                binary_versions[k].update(pkgs)
            else:
                binary_versions[k] = pkgs

    print(json.dumps(binary_versions))
