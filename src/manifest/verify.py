"""Package integrity manifest verification: executable specification.

A package root is a directory.  An unsigned manifest has this shape::

    {
        "format": "sec-integrity-manifest/1",
        "algorithm": "sha256",
        "files": {relative_posix_path: 64_char_lowercase_hex_sha256},
    }

A signed manifest is the same object plus a ``"signature"`` member holding a
64-character lowercase hex HMAC-SHA256.  The signature covers the canonical
JSON encoding of every member except ``"signature"``::

    json.dumps(payload, sort_keys=True, separators=(",", ":"),
               ensure_ascii=False).encode("utf-8")

Manifest paths use forward slashes and are relative to the package root.  No
path may escape the root: absolute paths, Windows drive paths, UNC paths, dot
segments and empty segments are all forbidden.  Every comparison in this
module has tolerance 0: file sets, digests and signatures must match exactly.

Only the standard library modules hashlib, hmac, json and os are used.
"""

import hashlib
import hmac
import json
import os

FORMAT = "sec-integrity-manifest/1"
ALGORITHM = "sha256"
_CHUNK_SIZE = 65536


def _canonical_bytes(manifest):
    """Return the canonical signed bytes of every member except ``signature``."""
    payload = {name: value for name, value in manifest.items() if name != "signature"}
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _sha256_file(path):
    """Hash a regular file with SHA-256 in fixed-size chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _is_inside(real_root, real_path):
    """True when ``real_path`` is ``real_root`` itself or strictly below it."""
    return real_path == real_root or real_path.startswith(real_root + os.sep)


def build_manifest(root, entries):
    """Return an unsigned manifest for the named files under ``root``.

    ``root`` is a directory path.  ``entries`` is an iterable of relative file
    paths.  Each entry must already be a canonical portable relative path for
    which :func:`path_allowed` returns true; this function does not silently
    repair dot segments, backslashes, drive letters or absolute paths.  An
    unsafe entry raises ``ValueError``.

    Join each entry below ``root`` and resolve both the root and the resulting
    file with ``os.path.realpath``.  The real file must stay inside the real
    root; a directory or file symlink that resolves outside the root must
    raise ``ValueError`` instead of hashing outside data.  The entry must name
    a regular file; a missing or non-regular file raises ``FileNotFoundError``.
    Reject duplicate entries with ``ValueError``.

    Hash only with SHA-256, in fixed-size chunks, and return::

        {
            "format": "sec-integrity-manifest/1",
            "algorithm": "sha256",
            "files": {relative_posix_path: digest},
        }

    ``files`` keys are the validated entry strings and are sorted for a
    deterministic result.  The manifest contains no absolute path, timestamp,
    random value or signature.  An empty ``entries`` produces an empty
    ``files`` mapping; :func:`verify_package`, not this builder, rejects an
    empty manifest.
    """
    real_root = os.path.realpath(os.fspath(root))
    files = {}
    for entry in entries:
        if not path_allowed(entry):
            raise ValueError("unsafe manifest path: %r" % (entry,))
        if entry in files:
            raise ValueError("duplicate manifest entry: %r" % (entry,))
        candidate = os.path.join(real_root, *entry.split("/"))
        real_file = os.path.realpath(candidate)
        if not _is_inside(real_root, real_file):
            raise ValueError("entry resolves outside the package root: %r" % (entry,))
        if not os.path.isfile(real_file):
            raise FileNotFoundError("no such regular file: %r" % (entry,))
        files[entry] = _sha256_file(real_file)
    return {
        "format": FORMAT,
        "algorithm": ALGORITHM,
        "files": {name: files[name] for name in sorted(files)},
    }


def sign_manifest(manifest, key):
    """Return a signed copy of an unsigned manifest.

    ``key`` is a bytes HMAC key.  ``manifest`` must be a mapping containing
    ``format``, ``algorithm`` and a ``files`` mapping; otherwise raise
    ``ValueError``.  Do not mutate the caller's object.

    The signed bytes are the canonical JSON of every manifest member except
    ``signature``, encoded as UTF-8.  The signature is the lowercase hex
    HMAC-SHA256 of those bytes.  Return a shallow copy with a ``signature``
    member; an existing signature is ignored and replaced.
    """
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a mapping")
    if "format" not in manifest or "algorithm" not in manifest:
        raise ValueError("manifest must carry format and algorithm")
    if not isinstance(manifest.get("files"), dict):
        raise ValueError("manifest must carry a files mapping")
    signed = dict(manifest)
    signed["signature"] = hmac.new(
        key, _canonical_bytes(manifest), hashlib.sha256
    ).hexdigest()
    return signed


def verify_signature(manifest, key):
    """Return true exactly when a signed manifest has a valid HMAC signature.

    Recompute the canonical JSON bytes of all manifest members except
    ``signature`` and the HMAC-SHA256 under ``key``.  Compare the expected
    lowercase hex value with the supplied ``signature`` through
    ``hmac.compare_digest`` exactly once.  Never use ordinary equality and
    never return early merely because the candidate has the wrong length:
    a truncated or otherwise malformed string still goes through that one
    constant-time comparison and then yields false.

    Return false, without raising, for a non-mapping manifest, a missing or
    non-string signature, a wrong key type or malformed content.  This
    function only authenticates the signed object; it does not read files.
    """
    if not isinstance(manifest, dict):
        return False
    supplied = manifest.get("signature")
    if not isinstance(supplied, str):
        return False
    try:
        expected = hmac.new(
            key, _canonical_bytes(manifest), hashlib.sha256
        ).hexdigest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected, supplied)


def compare(manifest, actual):
    """Compare an expected manifest with an actual digest mapping.

    ``manifest`` is the manifest mapping and ``actual`` is a mapping of
    relative package path to the digest observed on disk.  Do not verify a
    signature and do not read the filesystem here.  Return exactly::

        {
            "missing": sorted_expected_paths_absent_from_actual,
            "extra": sorted_actual_paths_absent_from_expected,
            "modified": sorted_common_paths_with_different_digests,
            "ok": bool,
        }

    ``missing``, ``extra`` and ``modified`` are lists of path strings in
    ascending order.  ``ok`` is true exactly when all three lists are empty.
    A missing or changed file must never hide an extra file: all three sets
    are compared on every call.  Raise ``ValueError`` when the manifest has no
    mapping under ``files`` or when ``actual`` is not a mapping.
    """
    expected = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(expected, dict):
        raise ValueError("manifest must carry a files mapping")
    if not isinstance(actual, dict):
        raise ValueError("actual must be a mapping of path to digest")
    missing = sorted(name for name in expected if name not in actual)
    extra = sorted(name for name in actual if name not in expected)
    modified = sorted(
        name
        for name in expected
        if name in actual and expected[name] != actual[name]
    )
    return {
        "missing": missing,
        "extra": extra,
        "modified": modified,
        "ok": not missing and not extra and not modified,
    }


def path_allowed(rel):
    """Return true exactly when ``rel`` is a safe canonical relative path.

    The check is lexical and must not depend on the current directory or on
    the filesystem.  A safe path is a non-empty ``str`` that uses only forward
    slashes, has no NUL or backslash, is not absolute, does not begin with a
    slash, and does not carry a Windows drive prefix such as ``C:`` or
    ``C:/``.  Every slash-separated segment must be non-empty and must be
    neither ``.`` nor ``..``.  Thus a trailing slash and a doubled slash are
    both rejected.

    Do not normalize the input and then accept it; a caller that passes a
    non-canonical path is a caller that may later make a different lexical
    decision.  Return false for non-string input.
    """
    if not isinstance(rel, str) or not rel:
        return False
    if "\x00" in rel or "\\" in rel:
        return False
    if rel.startswith("/"):
        return False
    if len(rel) >= 2 and rel[1] == ":" and rel[0].isalpha():
        return False
    for segment in rel.split("/"):
        if segment in ("", ".", ".."):
            return False
    return True


def verify_package(root, manifest, key, policy):
    """Verify one signed manifest and the package tree under ``root``.

    The security order is mandatory:

    1. Validate ``policy`` with :func:`validate_policy`.  Any problem raises
       ``ValueError``; there are no unsafe defaults.
    2. Require the exact format string, the SHA-256 algorithm and a signature,
       and call :func:`verify_signature` before touching ``root``, opening a
       file, hashing a file or scanning a directory.  A missing or invalid
       signature raises ``ValueError``.  This prevents unauthenticated data
       from being read first and checked later.
    3. Require a non-empty ``files`` mapping.  Every key must satisfy
       :func:`path_allowed`.  An empty manifest is an error, never a pass.
    4. Walk ``root`` without following symlinked directories.  For every
       directory and every file, resolve the real path with
       ``os.path.realpath`` and reject with ``ValueError`` any path that is
       not inside the real root.  A directory symlink that points outside the
       root must not be traversed or trusted, even when its lexical name looks
       contained.
    5. Hash every actual regular file with SHA-256 and compare the complete
       file set and every digest through :func:`compare`, with tolerance 0.

    Return exactly::

        {
            "ok": bool,
            "signature_ok": True,
            "missing": [str, ...],
            "extra": [str, ...],
            "modified": [str, ...],
        }

    ``ok`` is true only when all three lists are empty.  Missing, extra and
    modified files are normal verification results in this report.  Policy,
    signature, path and root-confinement failures raise ``ValueError`` because
    they are trust failures, not content differences.
    """
    problems = validate_policy(policy)
    if problems:
        raise ValueError("unsafe verification policy: %s" % ", ".join(problems))

    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a mapping")
    if manifest.get("format") != FORMAT:
        raise ValueError("unsupported manifest format")
    if manifest.get("algorithm") != ALGORITHM:
        raise ValueError("unsupported digest algorithm")
    if "signature" not in manifest:
        raise ValueError("manifest is not signed")
    if not verify_signature(manifest, key):
        raise ValueError("invalid manifest signature")

    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ValueError("manifest must name at least one file")
    for name in files:
        if not path_allowed(name):
            raise ValueError("unsafe manifest path: %r" % (name,))

    real_root = os.path.realpath(os.fspath(root))
    actual = {}
    for dirpath, dirnames, filenames in os.walk(real_root, followlinks=False):
        for dirname in dirnames:
            real_dir = os.path.realpath(os.path.join(dirpath, dirname))
            if not _is_inside(real_root, real_dir):
                raise ValueError(
                    "directory resolves outside the package root: %r" % (dirname,)
                )
        for filename in filenames:
            full = os.path.join(dirpath, filename)
            real_file = os.path.realpath(full)
            if not _is_inside(real_root, real_file):
                raise ValueError(
                    "file resolves outside the package root: %r" % (filename,)
                )
            if not os.path.isfile(real_file):
                continue
            relative = os.path.relpath(real_file, real_root).replace(os.sep, "/")
            actual[relative] = _sha256_file(real_file)

    difference = compare(manifest, actual)
    return {
        "ok": difference["ok"],
        "signature_ok": True,
        "missing": difference["missing"],
        "extra": difference["extra"],
        "modified": difference["modified"],
    }


def validate_policy(policy):
    """Return a list of policy problem codes; an empty list means valid.

    Verification policy is a mapping whose three required members must each
    be the actual boolean ``True``.  There are no permissive defaults.  Check
    and report in this order:

    * ``require_signature`` false or absent -> ``"signature_not_required"``;
    * ``forbid_extra`` false or absent -> ``"extra_files_not_rejected"``;
    * ``restrict_paths`` false or absent -> ``"paths_not_restricted"``.

    A non-mapping policy returns ``["policy_invalid"]``.  Unknown extra keys
    are ignored.  A policy that ignores extra files is invalid even if the
    other two switches are enabled.
    """
    if not isinstance(policy, dict):
        return ["policy_invalid"]
    problems = []
    if policy.get("require_signature") is not True:
        problems.append("signature_not_required")
    if policy.get("forbid_extra") is not True:
        problems.append("extra_files_not_rejected")
    if policy.get("restrict_paths") is not True:
        problems.append("paths_not_restricted")
    return problems


def manifest_batch(packages, policy):
    """Verify independent packages without sharing state between them.

    ``packages`` is a mapping of package name to a record::

        {
            "name": {
                "root": directory path,
                "manifest": signed manifest,
                "key": bytes HMAC key,
            },
        }

    Validate ``policy`` once and raise ``ValueError`` if it is invalid.  For
    every package call :func:`verify_package` with that package's own root,
    manifest and key.  Never reuse a manifest, an actual-file mapping, a
    digest or a root from another package: package N must be checked against
    package N's files only, so a file present in one package cannot satisfy
    or contaminate another.

    Return a mapping from package name to that package's verification report.
    If one package raises ``ValueError`` (bad policy is raised before the
    loop), record ``{"ok": False, "error": str(exc)}`` for that name and
    continue with the remaining packages.  Names are processed in sorted
    order for deterministic output.  Do not mutate the input.
    """
    problems = validate_policy(policy)
    if problems:
        raise ValueError("unsafe verification policy: %s" % ", ".join(problems))
    reports = {}
    for name in sorted(packages):
        record = packages[name]
        try:
            reports[name] = verify_package(
                record["root"], record["manifest"], record["key"], policy
            )
        except ValueError as exc:
            reports[name] = {"ok": False, "error": str(exc)}
    return reports
