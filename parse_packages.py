#!/usr/bin/env python3

import lzma
import debian.debian_support as debs
import json
import sys


def parse_packages_xz(path):
    packages = {}
    with lzma.open(path, "rt") as f:
        for p in debs.PackageFile(path, file_obj=f):
            temp = dict(p)
            source = temp['Source'] if 'Source' in temp else temp['Package']
            if(source not in packages):
                packages[source] = []
            packages[source].append(temp)

    return packages


if __name__ == "__main__":
    package_file = "test_data/Packages.xz"
    if(len(sys.argv) > 1):
        package_file = sys.argv[1]
    packages = parse_packages_xz(package_file)
    binary_versions = {
        k: {
            p['Package']: p['Version'] for p in v
        } for k, v in packages.items()
    }
    print(json.dumps(binary_versions))
