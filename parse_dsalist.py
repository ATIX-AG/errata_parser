#!/usr/bin/env python

import sys
import re
from json import JSONEncoder

REGEX_1ST_LINE = r"^\[(?P<date>[^]]+)\]\s*(?P<ident>[A-z0-9\-]+)\s*(?P<package_name>\S+)\s*-*\s*(?P<typ>.*)$"
REGEX_CVE_LINE = r"\s+{(?P<cves>[^}]*)}"
REGEX_REL_LINE = r"\s+\[(?P<release>[^\]]*)\]\s*-\s*(?P<package_name>\S+)\s*(?P<version>\S*)"
REGEX_NOT_LINE = r"\s+NOTE:"

re_1st = re.compile(REGEX_1ST_LINE)
re_cve = re.compile(REGEX_CVE_LINE)
re_rel = re.compile(REGEX_REL_LINE)
re_not = re.compile(REGEX_NOT_LINE)


class JSONDSAEncoder(JSONEncoder):
    def default(self, o):
        if(isinstance(o, DSA)):
            return o.dict()
        else:
            JSONEncoder.default(o)


class ParserException(RuntimeError):
    def __init__(self, lnum=-1, line=None, msg="ParserException", critical=True):
        RuntimeError.__init__(self, "at %d: %s (%r)" % (lnum, msg, line))
        self.lnum = lnum
        self.line = line
        self.critical = critical


class ParserError(ParserException):
    def __init__(self, *args, **kwargs):
        kwargs['critical'] = True
        ParserException.__init__(self, *args, **kwargs)


class ParserWarning(ParserException):
    def __init__(self, *args, **kwargs):
        kwargs['critical'] = False
        ParserException.__init__(self, *args, **kwargs)


class DSA():
    def __init__(self, date=None, ident=None, typ=None, package_name=None):
        self.date = date
        self.id = ident
        self.type = typ
        self.package_name = package_name
        self.versions = {}
        self.cve = []

    def add_cve(self, cve_numbers):
        self.cve = list(cve_numbers)

    def add_release(self, release, package_name, version):
        if(release not in self.versions):
            self.versions[release] = {}
        self.versions[release][package_name] = version

    def pp(self):
        print("%s from %s for %s" % (self.id, self.date, self.package_name))
        print("  CVE: %r" % self.cve)
        for rel in self.versions.keys():
            print("\t%s" % rel)
            rel_dict = self.versions[rel]
            for p in rel_dict.keys():
                print("\t\t%s %s" % (p, rel_dict[p]))

    def dict(self):
        return {
                'name': self.id,
                'date': self.date,
                'type': self.type,
                'package': self.package_name,
                'cve': self.cve,
                'versions': self.versions
                }


def parse_dsa_list(path):
    dsa = None
    dsa_list = []
    i = 0

    with open(path, "rw") as f:
        for line in f:
            try:
                i += 1
                res1 = re_1st.match(line)
                if(res1):
                    if(dsa):
                        dsa_list.append(dsa)
                    dsa = DSA(**res1.groupdict())
                elif(dsa):
                    res = re_rel.match(line)
                    if(res):
                        dsa.add_release(**res.groupdict())
                        continue
                    res = re_cve.match(line)
                    if(res):
                        if(res.lastindex > 0):
                            dsa.add_cve(res.group('cves').split(' '))
                        continue
                    if(re_not.match(line)):
                        # ignore 'NOTE:' lines
                        continue

                    raise ParserWarning(lnum=i, line=line, msg='Unknown Line in DSA')

                else:
                    raise ParserWarning(lnum=i, line=line, msg='Unknown Line')
            except ParserException as e:
                if(e.critical):
                    raise
                else:
                    sys.stderr.write("%s\n" % e)

    if(dsa):
        dsa_list.append(dsa)

    return dsa_list


if __name__ == "__main__":
    import json

    dsa_list = parse_dsa_list("test_data/dsa.list")

    print(json.dumps(dsa_list, cls=JSONDSAEncoder))

    #for dsa in dsa_list:
    #    dsa.pp()
