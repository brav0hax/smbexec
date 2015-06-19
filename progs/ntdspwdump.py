#!/usr/bin/env python

"""
Script to convert the output of NTDSXtract's dsusers.py script into a
pwdump-alike text format.

NTDSXtract is a framework developed by Csaba Barta in order to provide the
community with a solution to extract forensically important information from
the main database of Microsoft Active Directory (NTDS.DIT),
http://csababarta.com/en/ntdsxtract.html
"""

import os
import re
import sys


def usage():
    if len(sys.argv) != 2:
        print "usage: %s <output file of NTDSXtract's dsusers.py script>" % sys.argv[0]
        sys.exit(1)

def from_file(filename):
    if not os.path.exists(filename):
        print "file %s does not exist" % filename
        sys.exit(1)

    fp = open(filename, "rb")
    content = fp.read()
    fp.close()

    entries = re.findall("SAM Account name:\s+(.+?)\n.*?SID:\s+.*?-(\d+)\n.*?Password hashes:\n(.*?)Password history", content, re.I | re.S)

    for entry in entries:
        user, uid, hashes = entry
        lm_hash = "aad3b435b51404eeaad3b435b51404ee"
	nt_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"

        if hashes:
            hashes = hashes.replace("\n", "").split("\t")

            for h in hashes:
                if not h:
                    continue

                h = h.split(":")[1]

                if h.startswith("$NT$"):
                    nt_hash = h[4:]
                else:
                    lm_hash = h

        print "%s:%s:%s:%s:::" % (user, uid, lm_hash, nt_hash)

def main():
    usage()

    from_file(sys.argv[1])

if __name__ == "__main__":
    main()

