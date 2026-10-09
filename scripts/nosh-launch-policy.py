#!/usr/bin/env python3
"""Bounded local discovery hints and parsing of authoritative Guard status."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


def discover(workspace, workload='dev'):
    key = hashlib.sha256(workspace.encode()).hexdigest()
    paths = list((Path.home() / '.nosh/net-profiles').glob('*-' + key + ('-' + workload)))
    if len(paths) != 1:
        return None
    try:
        fd = os.open(paths[0] / 'current.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_size > 8 * 1024 * 1024):
                return None
            receipt = json.load(stream)
        if (receipt.get('kind') != 'NoshEgressProfileReceipt'
                or receipt.get('workspace', {}).get('path') != workspace
                or receipt.get('authoritative') is not False
                or receipt.get('workload') != workload):
            return None
        reference = receipt.get('latestCandidate') or receipt.get('approved')
        if not isinstance(reference, dict):
            return None
        # JSON escaping prevents receipt content from emitting terminal controls.
        return json.dumps({'image': reference.get('imageDigest'),
                           'revision': reference.get('revision')}, ensure_ascii=True)
    except (OSError, ValueError, AttributeError, TypeError):
        return None


def activation(workspace, workload='dev'):
    receipt = json.load(sys.stdin)
    if receipt.get('workspace', {}).get('path') != workspace:
        raise ValueError('Guard status belongs to another workspace')
    if receipt.get('integrity', {}).get('ok') is not True:
        raise ValueError('Guard could not verify workspace integrity')
    if receipt.get('workload') != workload:
        raise ValueError('Guard status belongs to another workload')
    active = receipt.get('activation') or {}
    revision = active.get('learnRevision', '')
    digest = active.get('leafBundleDigest', '')
    image = active.get('imageDigest', '')
    if (not isinstance(revision, str) or not re.fullmatch(r'[A-Za-z0-9_-]+', revision)
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest)
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', image)):
        raise ValueError('No applied policy with verified launch settings; resume nosh init')
    return '\n'.join([revision, digest, image])


if __name__ == '__main__':
    try:
        workspace = os.path.realpath(sys.argv[2])
        workload = sys.argv[3] if len(sys.argv) > 3 else 'dev'
        if workload not in ('dev', 'run'):
            raise ValueError('invalid workload')
        result = discover(workspace, workload) if sys.argv[1] == 'discover' else activation(workspace, workload)
        if result is None:
            sys.exit(1)
        print(result)
    except (ValueError, TypeError, AttributeError) as error:
        print(f'nosh: {error}', file=sys.stderr)
        sys.exit(1)
