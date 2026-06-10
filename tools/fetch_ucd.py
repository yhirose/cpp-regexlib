#!/usr/bin/env python3
"""
fetch_ucd.py — Download the pinned Unicode Character Database inputs that
generate_ucd.py consumes, and verify them against tools/ucd/SHA256SUMS.

The raw UCD text files are large and are NOT committed (see tools/ucd/.gitignore);
only the pinned VERSION + SHA256SUMS manifest and the generated tables (in
regexlib.h) live in the repo. Run this once before regenerating:

    python3 tools/fetch_ucd.py
    python3 tools/generate_ucd.py update regexlib.h

To bump Unicode versions: edit tools/ucd/VERSION, run this with --refresh-sums to
re-pin the manifest (review the diff!), then regenerate and re-run the tests.
"""

import argparse
import hashlib
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
UCD = os.path.join(HERE, "ucd")

# Files relative to https://www.unicode.org/Public/<VERSION>/ucd/
FILES = [
    "UnicodeData.txt",
    "PropList.txt",
    "CaseFolding.txt",
    "DerivedCoreProperties.txt",
    "auxiliary/GraphemeBreakProperty.txt",
    "auxiliary/GraphemeBreakTest.txt",
    "emoji/emoji-data.txt",
]


def version():
    return open(os.path.join(UCD, "VERSION")).read().strip()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest():
    sums = {}
    p = os.path.join(UCD, "SHA256SUMS")
    if not os.path.exists(p):
        return sums
    for line in open(p):
        line = line.strip()
        if line:
            digest, name = line.split(None, 1)
            sums[name.strip()] = digest
    return sums


def write_manifest(sums):
    with open(os.path.join(UCD, "SHA256SUMS"), "w") as f:
        for name in FILES:
            f.write("%s  %s\n" % (sums[name], name))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--refresh-sums", action="store_true",
                    help="re-pin SHA256SUMS to whatever is downloaded (review the diff!)")
    args = ap.parse_args()

    ver = version()
    base = "https://www.unicode.org/Public/%s/ucd/" % ver
    manifest = load_manifest()
    new_sums = {}
    failed = False

    for rel in FILES:
        dst = os.path.join(UCD, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        url = base + rel
        print("fetching %s" % url)
        urllib.request.urlretrieve(url, dst)
        digest = sha256(dst)
        new_sums[rel] = digest
        if not args.refresh_sums and rel in manifest and manifest[rel] != digest:
            print("  ERROR: checksum mismatch for %s\n    expected %s\n    got      %s"
                  % (rel, manifest[rel], digest), file=sys.stderr)
            failed = True

    if args.refresh_sums:
        write_manifest(new_sums)
        print("re-pinned tools/ucd/SHA256SUMS for Unicode %s" % ver)
    elif failed:
        sys.exit("checksum verification failed; refusing to proceed")
    else:
        print("OK: %d files verified against SHA256SUMS (Unicode %s)" % (len(FILES), ver))


if __name__ == "__main__":
    main()
