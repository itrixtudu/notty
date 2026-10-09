#!/usr/bin/env python3
"""Remember a verified tooling or review UI image without replacing other settings."""
import argparse
import os
from pathlib import Path
import re
import stat
import tempfile


def private_configuration(info):
    return (stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
            and info.st_size <= 65536)


def configuration_identity(info):
    return (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns,
            info.st_size, info.st_mode, info.st_uid, info.st_nlink)


def save_tooling(filename, image, setting='NOSH_POLICY_TOOLING_IMAGE', expected_image=None):
    if setting not in ('NOSH_POLICY_TOOLING_IMAGE', 'NOSH_POLICY_REVIEW_UI_IMAGE'):
        raise ValueError('unknown image configuration setting')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        raise ValueError('tooling must be an exact local image ID')
    target = Path(filename)
    if not target.is_absolute():
        raise ValueError('tooling configuration must be an absolute path')
    if target.resolve() != target or target.is_symlink():
        raise ValueError('tooling configuration must not traverse symlinks')
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = target.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
        raise ValueError('tooling configuration directory must be caller-owned and not writable by others')
    before = None
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        lines = []
    else:
        with os.fdopen(fd, encoding='utf-8') as stream:
            info = os.fstat(stream.fileno())
            if not private_configuration(info):
                raise ValueError('existing tooling configuration must be a private caller-owned regular file')
            before = configuration_identity(info)
            lines = stream.read(65537).splitlines()
    values = {}
    known = {'SCHEMA_VERSION', 'NOSH_POLICY_TOOLING_IMAGE', 'NOSH_POLICY_REVIEW_UI_IMAGE'}
    for line in lines:
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator or key not in known:
            raise ValueError('tooling configuration contains an unknown or malformed setting')
        if key in values:
            raise ValueError('tooling configuration contains duplicate settings')
        values[key] = value
        if key == 'SCHEMA_VERSION':
            if value != '1':
                raise ValueError('tooling configuration uses an unsupported schema version')
        elif value and not re.fullmatch(r'sha256:[a-f0-9]{64}', value):
            raise ValueError('configured images must be exact local image IDs or blank')
    if expected_image is not None and values.get(setting, '') != expected_image:
        raise ValueError('image selection changed during preparation; refusing to replace it')
    prefix = setting + '='
    updated = [prefix + image if line.startswith(prefix) else line for line in lines]
    if 'SCHEMA_VERSION' not in values:
        updated.insert(0, 'SCHEMA_VERSION=1')
    for key in ('NOSH_POLICY_TOOLING_IMAGE', 'NOSH_POLICY_REVIEW_UI_IMAGE'):
        if key not in values:
            updated.append(key + '=' + (image if key == setting else ''))
    contents = '\n'.join(updated) + '\n'
    descriptor, temporary = tempfile.mkstemp(prefix='.wizard-tooling.', dir=target.parent)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        if before is None:
            # Exclusive publication cannot replace a concurrently created file.
            os.link(temporary, target, follow_symlinks=False)
        else:
            current = target.lstat()
            if not private_configuration(current) or configuration_identity(current) != before:
                raise ValueError('tooling configuration changed; refusing to replace it')
            os.replace(temporary, target)
        return str(target)
    finally:
        Path(temporary).unlink(missing_ok=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    config = Path(os.environ.get('NOSH_PROFILE_REVIEW_IMAGE_CONFIG',
        str(Path(os.environ.get('XDG_CONFIG_HOME', str(Path.home() / '.config')))
            / 'nosh/policy-review-images.conf')))
    try:
        print('Remembered verified tooling image in ' + save_tooling(config, args.image))
    except (OSError, ValueError) as error:
        parser.exit(1, f'nosh tooling: {error}\n')
