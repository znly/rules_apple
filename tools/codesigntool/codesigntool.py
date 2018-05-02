import argparse
import base64
import json
import os
import plistlib
import re
import subprocess
import sys

def _check_output(args, inputstr=None):
    proc = subprocess.Popen(args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    return proc.communicate(input=inputstr)[0]

def mobileprovision(mobileprovision_file):
    plist_xml = subprocess.check_output([
        "security", "cms",
        "-D",
        "-i", mobileprovision_file,
    ])
    return plistlib.readPlistFromString(plist_xml)

def fingerprint(identity):
    fingerprint = _check_output([
        "openssl", "x509", "-inform", "DER", "-noout", "-fingerprint",
    ], inputstr=identity).strip()
    fingerprint = fingerprint.replace("SHA1 Fingerprint=", "")
    fingerprint = fingerprint.replace(":", "")
    return fingerprint

def identities(mpf):
    for identity in mpf["DeveloperCertificates"]:
        yield fingerprint(identity.data)

def identities_codesign():
    ids = []
    output = _check_output([
        "security", "find-identity", "-v", "-p", "codesigning",
    ]).strip()
    for line in output.split("\n"):
        m = re.search(r"([A-F0-9]{40})", line)
        if m:
            ids.append(m.group(0))
    return ids

def codesign_identity(args):
    mpf = mobileprovision(args.mobileprovision)
    ids_codesign = set(identities_codesign())
    for id_mpf in identities(mpf):
        if id_mpf in ids_codesign:
            return id_mpf

def main(argv):
    parser = argparse.ArgumentParser(description='codesign wrapper')
    parser.add_argument('--mobileprovision', type=str, help='mobileprovision file')
    parser.add_argument('--codesign', type=str, help='path to codesign binary')
    args, codesign_args = parser.parse_known_args()
    identity = codesign_identity(args)
    if not identity:
        return 1
    print("Found matching identity: %s" % identity)
    os.execve(args.codesign, [args.codesign, "-v", "--sign", identity] + codesign_args, os.environ)

if __name__ == '__main__':
    sys.exit(main(sys.argv))
