#!/usr/bin/env python3
"""Run the unchanged Hayabusa harness against another verified review binary.

Example:
  python3 review_compatibility.py --review-binary /path/to/velociraptor-0.77.3 \
    --extended --artifact /path/to/analyzer.yaml --monitor /path/to/monitor.yaml

All other arguments pass through to test.py. Existing pinned 0.77.2 results
are not overwritten; choose a new workdir and retain the resulting report.
"""
import argparse
import hashlib
from pathlib import Path
import sys

from review_timeout import BINARY_HASHES
import test as harness


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--review-binary', type=Path, required=True)
    args, remaining = parser.parse_known_args()
    binary = args.review_binary.resolve()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest not in BINARY_HASHES:
        raise RuntimeError('Review binary does not match a verified release hash')
    harness.DOWNLOADS['velociraptor'] = (binary.as_uri(), digest)
    sys.argv = [str(Path(harness.__file__).resolve()), *remaining]
    harness.main()


if __name__ == '__main__':
    main()
