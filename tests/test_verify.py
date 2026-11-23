"""Executable acceptance tests for package integrity manifest verification.

These 15 tests are immutable.  They exercise the eight stubs in
``src/manifest/verify.py`` and use only the standard library plus pytest.
The reference signer below is deliberately independent of the implementation
so targeted tests can construct signed manifests without calling the stubs.
"""

import hashlib
import hmac
import json
import os

import pytest

from manifest import verify

KEY = b"package-signing-key-v1"
POLICY = {
    "require_signature": True,
    "forbid_extra": True,
    "restrict_paths": True,
}
FORMAT = "sec-integrity-manifest/1"


def sha256_hex(data):
    """Return the lowercase SHA-256 hex digest of bytes."""
    return hashlib.sha256(data).hexdigest()


def reference_signature(manifest, key=KEY):
    """Independent HMAC-SHA256 signer for the manifest contract."""
    payload = {name: value for name, value in manifest.items() if name != "signature"}
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hmac.new(key, encoded, hashlib.sha256).hexdigest()


def signed_manifest(files, key=KEY):
    """Return a correctly signed manifest for a mapping of path to digest."""
    manifest = {
        "format": FORMAT,
        "algorithm": "sha256",
        "files": dict(files),
    }
    manifest["signature"] = reference_signature(manifest, key)
    return manifest


def test_build_manifest_rejects_parent_escape(tmp_path):
    """A dot-dot entry must not be joined and hashed outside the root."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "inside.txt").write_text("inside", encoding="utf-8")
    (tmp_path / "outside.txt").write_text("outside", encoding="utf-8")

    with pytest.raises(ValueError):
        verify.build_manifest(root, ["inside.txt", "../outside.txt"])


def test_path_allowed_rejects_windows_drive_path():
    """A drive path is absolute on Windows even without a leading slash."""
    assert verify.path_allowed("C:/Windows/win.ini") is False
    assert verify.path_allowed("C:Windows/win.ini") is False
    assert verify.path_allowed("docs/readme.txt") is True


def test_compare_reports_extra_files():
    """Comparison must report files present on disk but absent from manifest."""
    manifest = {
        "format": FORMAT,
        "algorithm": "sha256",
        "files": {"a.txt": sha256_hex(b"a")},
    }
    actual = {
        "a.txt": sha256_hex(b"a"),
        "b.txt": sha256_hex(b"b"),
    }

    difference = verify.compare(manifest, actual)

    assert difference == {
        "missing": [],
        "extra": ["b.txt"],
        "modified": [],
        "ok": False,
    }


def test_verify_package_verifies_signature_before_reading_files(tmp_path, monkeypatch):
    """An invalid signature must be rejected before the package is scanned."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("a", encoding="utf-8")
    manifest = signed_manifest({"a.txt": sha256_hex(b"a")})
    seen = []

    def fake_verify_signature(candidate, key):
        seen.append("signature")
        return False

    def forbidden_walk(*args, **kwargs):
        seen.append("filesystem")
        raise AssertionError("package was scanned before signature verification")

    monkeypatch.setattr(verify, "verify_signature", fake_verify_signature)
    monkeypatch.setattr(verify.os, "walk", forbidden_walk)

    with pytest.raises(ValueError):
        verify.verify_package(root, manifest, KEY, POLICY)

    assert seen == ["signature"]


def test_verify_signature_uses_constant_time_compare(monkeypatch):
    """Signature comparison must call hmac.compare_digest on equal lengths."""
    manifest = signed_manifest({"a.txt": sha256_hex(b"a")})
    seen = []
    real_compare = hmac.compare_digest

    def spy(left, right):
        seen.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)

    assert verify.verify_signature(manifest, KEY) is True
    assert len(seen) == 1
    assert len(seen[0][0]) == len(seen[0][1])


def test_build_manifest_uses_sha256(tmp_path):
    """Manifest hashes must be SHA-256, not a collision-prone weak digest."""
    root = tmp_path / "root"
    root.mkdir()
    content = b"release-payload-0001"
    (root / "payload.bin").write_bytes(content)

    manifest = verify.build_manifest(root, ["payload.bin"])

    assert manifest["format"] == FORMAT
    assert manifest["algorithm"] == "sha256"
    assert manifest["files"]["payload.bin"] == hashlib.sha256(content).hexdigest()


def test_verify_package_rejects_empty_manifest(tmp_path):
    """An empty file set must never be treated as a successful verification."""
    root = tmp_path / "root"
    root.mkdir()
    manifest = signed_manifest({})

    with pytest.raises(ValueError):
        verify.verify_package(root, manifest, KEY, POLICY)


def test_validate_policy_rejects_ignoring_extra_files():
    """A policy that permits extra files must be reported as unsafe."""
    assert verify.validate_policy(POLICY) == []

    weak = dict(POLICY)
    weak["forbid_extra"] = False

    assert verify.validate_policy(weak) == ["extra_files_not_rejected"]


def test_manifest_batch_does_not_reuse_actual_files(tmp_path):
    """Each package must be compared with its own root and manifest."""
    root_alpha = tmp_path / "alpha"
    root_beta = tmp_path / "beta"
    root_alpha.mkdir()
    root_beta.mkdir()
    alpha_bytes = b"alpha-only"
    beta_bytes = b"beta-only"
    (root_alpha / "alpha.txt").write_bytes(alpha_bytes)
    (root_beta / "beta.txt").write_bytes(beta_bytes)

    packages = {
        "alpha": {
            "root": root_alpha,
            "manifest": signed_manifest({"alpha.txt": sha256_hex(alpha_bytes)}),
            "key": KEY,
        },
        "beta": {
            "root": root_beta,
            "manifest": signed_manifest({"beta.txt": sha256_hex(beta_bytes)}),
            "key": KEY,
        },
    }

    reports = verify.manifest_batch(packages, POLICY)

    assert reports["alpha"] == {
        "ok": True,
        "signature_ok": True,
        "missing": [],
        "extra": [],
        "modified": [],
    }
    assert reports["beta"] == {
        "ok": True,
        "signature_ok": True,
        "missing": [],
        "extra": [],
        "modified": [],
    }


def test_verify_package_rejects_symlinked_directory_escape(tmp_path, monkeypatch):
    """A directory that resolves outside the root must be rejected.

    Creating a real directory symlink needs a Windows privilege, so the test
    simulates one: link is a normal directory whose lexical location is inside
    root, but islink and realpath both report an outside target.  A verifier
    that trusts only the joined lexical path will read outside the package.
    """
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "link").mkdir()
    payload = b"outside-payload"
    (root / "link" / "payload.txt").write_bytes(payload)
    manifest = signed_manifest({"link/payload.txt": sha256_hex(payload)})

    link_abs = os.path.abspath(os.fspath(root / "link"))
    outside_abs = os.path.abspath(os.fspath(outside))
    real_realpath = os.path.realpath
    real_islink = os.path.islink

    def fake_realpath(path):
        raw = os.path.abspath(os.fspath(path))
        if raw == link_abs:
            return outside_abs
        if raw.startswith(link_abs + os.sep):
            return outside_abs + raw[len(link_abs):]
        return real_realpath(path)

    def fake_islink(path):
        raw = os.path.abspath(os.fspath(path))
        if raw == link_abs or raw.startswith(link_abs + os.sep):
            return True
        return real_islink(path)

    monkeypatch.setattr(verify.os.path, "realpath", fake_realpath)
    monkeypatch.setattr(verify.os.path, "islink", fake_islink)

    with pytest.raises(ValueError):
        verify.verify_package(root, manifest, KEY, POLICY)


def test_complete_package_passes(tmp_path):
    """A complete, correctly signed package returns a clean report."""
    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    (root / "config").mkdir()
    app = b"application-binary"
    settings = b'{"enabled": true}'
    (root / "bin" / "app.exe").write_bytes(app)
    (root / "config" / "settings.json").write_bytes(settings)

    manifest = verify.build_manifest(
        root,
        ["bin/app.exe", "config/settings.json"],
    )
    signed = verify.sign_manifest(manifest, KEY)

    assert signed["signature"] == reference_signature(manifest, KEY)
    assert verify.verify_package(root, signed, KEY, POLICY) == {
        "ok": True,
        "signature_ok": True,
        "missing": [],
        "extra": [],
        "modified": [],
    }


def test_missing_file_is_reported(tmp_path):
    """A manifest entry with no file on disk must appear under missing."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"a")
    manifest = signed_manifest(
        {
            "a.txt": sha256_hex(b"a"),
            "b.txt": sha256_hex(b"b"),
        }
    )

    report = verify.verify_package(root, manifest, KEY, POLICY)

    assert report["signature_ok"] is True
    assert report["missing"] == ["b.txt"]
    assert report["extra"] == []
    assert report["modified"] == []
    assert report["ok"] is False


def test_extra_file_is_reported(tmp_path):
    """A file on disk but absent from the manifest must appear under extra."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"a")
    (root / "b.txt").write_bytes(b"b")
    manifest = signed_manifest({"a.txt": sha256_hex(b"a")})

    report = verify.verify_package(root, manifest, KEY, POLICY)

    assert report["signature_ok"] is True
    assert report["missing"] == []
    assert report["extra"] == ["b.txt"]
    assert report["modified"] == []
    assert report["ok"] is False


def test_tampered_signature_is_rejected(tmp_path):
    """Changing the manifest signature must fail authentication and verify."""
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"a")
    manifest = signed_manifest({"a.txt": sha256_hex(b"a")})

    original = manifest["signature"]
    replacement = "0" if original[0] != "0" else "1"
    tampered = dict(manifest)
    tampered["signature"] = replacement + original[1:]

    assert verify.verify_signature(tampered, KEY) is False
    with pytest.raises(ValueError):
        verify.verify_package(root, tampered, KEY, POLICY)


def test_batch_results_match_individual_verification(tmp_path):
    """Batch reports for independent packages match direct verification."""
    root_one = tmp_path / "one"
    root_two = tmp_path / "two"
    root_one.mkdir()
    root_two.mkdir()
    one_bytes = b"one-package"
    two_bytes = b"two-package"
    (root_one / "one.txt").write_bytes(one_bytes)
    (root_two / "two.txt").write_bytes(two_bytes)

    packages = {
        "one": {
            "root": root_one,
            "manifest": signed_manifest({"one.txt": sha256_hex(one_bytes)}),
            "key": KEY,
        },
        "two": {
            "root": root_two,
            "manifest": signed_manifest({"two.txt": sha256_hex(two_bytes)}),
            "key": KEY,
        },
    }

    individual = {
        name: verify.verify_package(
            record["root"],
            record["manifest"],
            record["key"],
            POLICY,
        )
        for name, record in packages.items()
    }

    assert verify.manifest_batch(packages, POLICY) == individual
