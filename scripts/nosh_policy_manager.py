"""Private, read-only discovery and exact-scope checks for wizard reviews."""
import json
import os
from pathlib import Path
import stat


def private_json(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor) as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > 8 * 1024 * 1024):
            raise ValueError('Expected a private, caller-owned review file')
        raw = stream.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError('Review metadata exceeds size limit')
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError('Invalid review metadata')
        return value


def validate_report(path, workspace):
    directory = Path(path).resolve(strict=True)
    left = private_json(directory / 'allow.json').get('history_scope', {})
    right = private_json(directory / 'not-yet.json').get('history_scope', {})
    workspace = Path(workspace).resolve()
    if (not isinstance(left, dict) or left != right
            or left.get('kind') not in ('repo', 'directory') or not left.get('root')):
        raise ValueError('Choose a report with an explicit repo or directory scope')
    root = Path(left['root']).resolve(strict=True)
    if workspace != root and (left['kind'] != 'repo' or root not in workspace.parents):
        raise ValueError('Tool report belongs to another workspace')
    if any(workspace == Path(p) or Path(p) in workspace.parents
           for p in left.get('excluded_roots', [])):
        raise ValueError('This workspace was excluded from the tool report')
    return str(directory)


def discover_reports(workspace, explicit=''):
    root = Path(os.environ.get('XDG_STATE_HOME', str(Path.home() / '.local/state'))) / 'nosh/codex-tool-audit'
    try:
        candidates = sorted(root.iterdir(), reverse=True)[:256]
    except OSError:
        candidates = []
    if explicit:
        candidates.insert(0, Path(explicit))
    result = []
    for candidate in candidates:
        try:
            path = validate_report(candidate, workspace)
            if path not in result:
                result.append(path)
        except (OSError, ValueError, TypeError):
            continue
    return result


def validate_session(path, workspace, image_id, revision, workload):
    session = private_json(Path(path) / 'runtime/review-session.json')
    if (session.get('workdir') != str(Path(workspace).resolve())
            or session.get('imageDigest') != image_id or session.get('revision') != revision):
        raise ValueError('Review scope changed; refresh and select the exact image/revision')
    candidate = private_json(Path(session['runtimeCandidate']) / 'egress-profile.json')
    value = candidate
    for key in ('spec', 'launch', 'config', 'workload'):
        value = value.get(key) if isinstance(value, dict) else None
    if value != workload:
        raise ValueError('Review belongs to another workload')
    return session
