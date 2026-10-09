"""Private, offline unique-request evidence. Never evaluates recorded input."""
import hashlib
import json
import os
from pathlib import Path
import sqlite3

NAME = 'requests.sqlite3'
MAX_BYTES = 2 * 1024 * 1024 * 1024


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'))


def file_digest(path):
    with Path(path).open('rb') as stream:
        return 'sha256:' + hashlib.file_digest(stream, 'sha256').hexdigest()


class Evidence:
    def __init__(self, directory):
        self.path = Path(directory) / NAME
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(self.path)
        self.db.executescript('''
            PRAGMA journal_mode=DELETE;
            PRAGMA user_version=1;
            CREATE TABLE requests (
                id TEXT PRIMARY KEY, group_id TEXT NOT NULL, tool TEXT NOT NULL,
                input_json TEXT NOT NULL, cwd TEXT, occurrences INTEGER NOT NULL,
                source TEXT NOT NULL, line INTEGER NOT NULL
            ) WITHOUT ROWID;
            CREATE INDEX request_groups ON requests(group_id, id);
        ''')
        self.pending = 0

    def add(self, payload, tool, category, form, reason, cwd, source, line):
        value = payload.get('arguments', payload.get('input'))
        if value is None:
            value = {k: v for k, v in payload.items()
                     if k not in ('id', 'call_id', 'status', 'internal_chat_message_metadata_passthrough')}
        if isinstance(value, str):
            try:
                decoded = json.loads(value)
                if isinstance(decoded, (dict, list)):
                    value = decoded
            except ValueError:
                pass
        effective = str(cwd) if cwd is not None else None
        if isinstance(value, dict):
            requested = value.get('workdir', value.get('cwd'))
            if isinstance(requested, str) and requested and '\0' not in requested:
                effective = os.path.normpath(requested if requested.startswith('/') else
                                            os.path.join(effective, requested)) if effective or requested.startswith('/') else requested
        identity = hashlib.sha256(canonical([tool, value, effective]).encode()).hexdigest()
        # Must match the existing JS/Python group identity, independent of JSON key order.
        group = hashlib.sha256(json.dumps([category, tool, form, reason],
                               ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        self.db.execute('''INSERT INTO requests VALUES (?,?,?,?,?,1,?,?)
            ON CONFLICT(id) DO UPDATE SET occurrences=occurrences+1''',
            (identity, group, tool, canonical(value), effective, source, line))
        self.pending += 1
        if self.pending >= 1000:
            self.db.commit()
            self.pending = 0
            if self.path.stat().st_size > MAX_BYTES:
                raise ValueError('Request evidence exceeds the 2 GiB limit')

    def finish(self):
        self.db.commit()
        unique, recorded = self.db.execute('SELECT count(*), coalesce(sum(occurrences),0) FROM requests').fetchone()
        self.db.close()
        if self.path.stat().st_size > MAX_BYTES:
            raise ValueError('Request evidence exceeds the 2 GiB limit')
        return {'schemaVersion': 1, 'file': NAME, 'digest': file_digest(self.path),
                'bytes': self.path.stat().st_size, 'uniqueRequests': unique,
                'recordedRequests': recorded, 'originalInputs': True}

    def abort(self):
        self.db.close()
        self.path.unlink(missing_ok=True)
        self.path.with_name(NAME + '-journal').unlink(missing_ok=True)
