import hashlib
import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('signing_setup', Path(__file__).resolve().parents[1] / 'scripts/nosh-signing-setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


def fixture_script(guard):
    # Exercise the actual installer transaction in a temporary directory without
    # elevation. Only expected ownership is mapped to the test process identity.
    uid, gid = os.getuid(), os.getgid()
    return (setup.INSTALL_PUBLIC_TRUST.replace('/etc/nosh-guard', str(guard))
        .replace('-o root -g root', f'-o {uid} -g {gid}')
        .replace('== 0 ]]', f'== {uid} ]]')
        .replace("'0:600:1'", f"'{uid}:600:1'")
        .replace("'0:700'", f"'{uid}:700'"))


class PublicTrustInstallation(unittest.TestCase):
    def test_exclusive_install_resume_and_changed_material_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            guard, source = base / 'guard', base / 'public'
            guard.mkdir(mode=0o700)
            source.mkdir(mode=0o700)
            files = ['review-public.pem', 'deployment-public.pem', 'trust.json']
            for name in files:
                (source / name).write_text('reviewed-public-material:' + name)
            hashes = [hashlib.sha256((source / name).read_bytes()).hexdigest() for name in files]
            script = fixture_script(guard)
            keys = guard / ('ebpf-trust-' + 'a' * 32)
            args = ['bash', '-c', script, 'test', str(source), str(keys), *hashes]
            first = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(first.returncode, 0, first.stderr)
            trust = guard / 'ebpf-deployment-trust.json'
            original = trust.read_bytes()
            self.assertEqual(trust.stat().st_mode & 0o777, 0o600)
            self.assertEqual(trust.stat().st_nlink, 1)
            self.assertEqual(sorted(p.name for p in keys.iterdir()), files[:2][::-1])
            self.assertEqual(subprocess.run(args, capture_output=True).returncode, 0)
            (source / 'trust.json').write_text('replacement')
            args[-1] = hashlib.sha256(b'replacement').hexdigest()
            self.assertNotEqual(subprocess.run(args, capture_output=True).returncode, 0)
            self.assertEqual(trust.read_bytes(), original)

    def test_hash_mismatch_never_installs_trust(self):
        with tempfile.TemporaryDirectory() as temporary:
            guard = Path(temporary) / 'guard'
            source = Path(temporary) / 'public'
            guard.mkdir(mode=0o700)
            source.mkdir(mode=0o700)
            for name in ('review-public.pem', 'deployment-public.pem', 'trust.json'):
                (source / name).write_text('changed-after-review')
            script = fixture_script(guard)
            result = subprocess.run(['bash', '-c', script, 'test', str(source),
                str(guard / ('ebpf-trust-' + 'a' * 32)), *(['0' * 64] * 3)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((guard / 'ebpf-deployment-trust.json').exists())


if __name__ == '__main__':
    unittest.main()
