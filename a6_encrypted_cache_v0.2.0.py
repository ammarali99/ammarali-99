#!/usr/bin/env python3
"""
a6_encrypted_cache.py -- Module A6 (Encrypted local cache) of the offline
network diagnostic app.

VERSION: 0.2.0
CHANGELOG:
  0.2.0 - Adds a `snapshots` table for A4 (Snapshot/Rollback Manager),
          the next module now being built. Same reasoning as v0.1.0's
          own scope decision: only add a table when the module that
          needs it actually exists, not ahead of time.

          Schema mirrors `findings`: `target` (e.g. an interface name
          like "Ethernet") and `snapshot_type` (e.g.
          "interface_admin_state") stay in the clear -- non-sensitive,
          and A4 needs to filter "give me the latest snapshot for this
          interface" without decrypting every row. `restored_at` also
          stays in the clear (NULL until a restore actually happens) so
          it's easy to see at a glance which snapshots were ever used.
          Everything else -- the actual captured state dict, and the
          human-readable `reason` a snapshot was taken -- goes into one
          encrypted BLOB column, same as a finding's target/summary/
          detail/evidence.

          New API: `write_snapshot()`, `get_snapshots()` (filterable by
          target/snapshot_type), `get_snapshot(id)` (direct lookup by
          id -- A4's restore/verify functions need to fetch one exact
          snapshot, not filter a list client-side the way A2 v0.7.0 had
          to work around A6 not having this for scans). New CLI:
          `--list-snapshots`, `--target` filter.

          Verified: wrote a throwaway snapshot with a canary string via
          `write_snapshot()`, read it back via both `get_snapshots()`
          and `get_snapshot(id)`, confirmed both decrypt correctly and
          the raw `.db` bytes don't contain the canary -- same
          encryption sanity check `--selftest` already does for scans/
          findings, now covering the new table too.

  0.1.0 - First version. Every other module is supposed to write here
          first (see CLAUDE.md's architecture table), so this starts with
          just the two things that actually exist so far: A1's scan
          output and A2's findings. fix_outcomes / snapshots / ai
          suggestions / reports get their own tables when A3/A4/AI1/A5
          exist -- no point designing storage for modules that aren't
          built yet.

          Encryption: SQLite has no encryption of its own, and Python's
          standard library has no safe symmetric-cipher primitive
          (hashlib does hashing, not encryption) -- writing one by hand
          would mean rolling our own crypto for a database that's meant
          to eventually hold router credentials, which is exactly the
          kind of thing you don't hand-roll. Ammar approved adding the
          `cryptography` package (PyPI, widely audited, the standard
          choice for this in Python) as an explicit, flagged exception
          to the "standard-library-only" convention -- it's a build-time
          dependency that gets bundled into the final installer, so it
          doesn't add install friction for the non-technical end user,
          only for development right now.

          Not every column is encrypted. finding_id/rule_id/category/
          severity/fix_classification/detected_at/source_version/
          scanned_at are stored in the clear, because AI1 and A3 will
          need to filter and join on exactly these fields later (e.g.
          "give me every auto-fixable finding" or "how has this finding
          trended across scans") without decrypting every row just to
          check a severity level, and none of them reveal anything about
          the customer's actual network. Everything that could --
          hostnames, IPs, MACs, Wi-Fi SSIDs, the full A1 discovery dict,
          a finding's target/summary/detail/evidence -- goes into an
          encrypted BLOB column (Fernet/AES-128-CBC+HMAC via
          `cryptography`), one blob per row, so a leaked or copied .db
          file exposes only that a scan happened and roughly what kind
          of thing was found, never the specifics.

          Key management (v1, flagged as a known gap): the Fernet key is
          a random 32 bytes generated on first run and stored in a
          sibling file next to the database, with owner-only permissions
          (chmod 600) on Linux/macOS. This protects the data if the .db
          file alone is copied elsewhere, but NOT against someone with
          full filesystem access to this machine, since the key sits
          right next to the data it unlocks. Real protection against
          that needs OS-keychain integration (Windows DPAPI / macOS
          Keychain / Linux Secret Service via the `keyring` package) --
          deferred, since that's a second new dependency and a bigger
          design decision (the Credential Manager will need the same
          answer), not something to fold into A6's first version
          silently. chmod 600 is also a no-op on Windows (no POSIX
          permission bits) -- there, the key file currently has whatever
          permissions the OS default gives it. Both gaps are the same
          shape as A1's other "real but partial" protections (e.g. the
          Wi-Fi radio-off check not reading Windows' actual Airplane
          Mode flag) -- stated honestly rather than silently assumed
          away.

          CLI here is a bridge, not the final design: `--import-scan`
          and `--import-findings` read A1's/A2's existing --json exports
          so Ammar can test the whole encrypt/store/retrieve round trip
          today without A1/A2 needing to change yet. The real plumbing
          change CLAUDE.md describes (A1/A2 writing here directly
          instead of through a JSON file) is next, once this is verified
          against real data.
"""

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.fernet import Fernet, InvalidToken
except ImportError:
    print(
        "Module A6 needs the 'cryptography' package (pip install cryptography) --\n"
        "this is a deliberate, flagged exception to the standard-library-only rule,\n"
        "see the VERSION 0.1.0 changelog at the top of this file for why.",
        file=sys.stderr,
    )
    raise

DEFAULT_DB_PATH = "network_cache.db"
DEFAULT_KEY_PATH = "network_cache.key"

# Finding columns kept in the clear -- non-sensitive, and A3/AI1 need to
# filter/join on them without decrypting every row. Everything else about
# a finding (target, summary, detail, evidence) is encrypted.
_FINDING_PLAIN_FIELDS = (
    "finding_id", "rule_id", "category", "severity", "fix_classification", "detected_at",
)
_FINDING_SENSITIVE_FIELDS = ("target", "summary", "detail", "evidence")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scanned_at TEXT NOT NULL,
    source_version TEXT,
    payload BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scans(id),
    finding_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    fix_classification TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    payload BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_finding_id ON findings(finding_id);

CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    target TEXT NOT NULL,
    snapshot_type TEXT NOT NULL,
    restored_at TEXT,
    payload BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_snapshots_target ON snapshots(target);
CREATE INDEX IF NOT EXISTS idx_snapshots_type ON snapshots(snapshot_type);
"""


def _load_or_create_key(key_path):
    path = Path(key_path)
    if path.exists():
        return path.read_bytes()
    key = Fernet.generate_key()
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # best-effort; no POSIX permission bits on Windows (known gap, see changelog)
    return key


class CacheError(Exception):
    """Raised for A6-specific failures (bad key, corrupt/tampered data)."""


class A6Cache:
    """
    Encrypted local cache. Every module is meant to write here first --
    this version handles A1's scan output and A2's findings, since those
    are the only two modules that exist so far.
    """

    def __init__(self, db_path=DEFAULT_DB_PATH, key_path=DEFAULT_KEY_PATH):
        self.db_path = db_path
        self.key_path = key_path
        self._fernet = Fernet(_load_or_create_key(key_path))
        self._conn = sqlite3.connect(db_path)
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def _encrypt(self, obj):
        return self._fernet.encrypt(json.dumps(obj).encode("utf-8"))

    def _decrypt(self, blob):
        try:
            raw = self._fernet.decrypt(bytes(blob))
        except InvalidToken:
            raise CacheError(
                f"Could not decrypt a row in {self.db_path} with the key at {self.key_path} "
                "-- wrong key file, or the database was tampered with."
            )
        return json.loads(raw.decode("utf-8"))

    def write_scan(self, discovery_data, source_version=None, scanned_at=None):
        """Stores one A1 discovery result. Returns the new scan's id."""
        scanned_at = scanned_at or datetime.now(timezone.utc).isoformat()
        payload = self._encrypt(discovery_data)
        cur = self._conn.execute(
            "INSERT INTO scans (scanned_at, source_version, payload) VALUES (?, ?, ?)",
            (scanned_at, source_version, payload),
        )
        self._conn.commit()
        return cur.lastrowid

    def write_findings(self, findings, scan_id=None):
        """
        Stores A2 findings, one row each. scan_id links them back to the
        scan they came from (nullable -- findings can be stored without a
        scan if that's ever useful, e.g. imported from elsewhere).
        """
        rows = []
        for f in findings:
            missing = [field for field in _FINDING_PLAIN_FIELDS if field not in f]
            if missing:
                raise CacheError(f"Finding is missing required field(s) {missing}: {f}")
            sensitive = {field: f.get(field) for field in _FINDING_SENSITIVE_FIELDS}
            rows.append((
                scan_id,
                f["finding_id"], f["rule_id"], f["category"], f["severity"],
                f["fix_classification"], f["detected_at"],
                self._encrypt(sensitive),
            ))
        self._conn.executemany(
            "INSERT INTO findings "
            "(scan_id, finding_id, rule_id, category, severity, fix_classification, "
            "detected_at, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        self._conn.commit()
        return len(rows)

    def get_scans(self, limit=10):
        rows = self._conn.execute(
            "SELECT id, scanned_at, source_version, payload FROM scans "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "id": r[0], "scanned_at": r[1], "source_version": r[2],
                "discovery": self._decrypt(r[3]),
            }
            for r in rows
        ]

    def get_findings(self, scan_id=None, severity=None, category=None, fix_classification=None):
        query = (
            "SELECT id, scan_id, finding_id, rule_id, category, severity, "
            "fix_classification, detected_at, payload FROM findings WHERE 1=1"
        )
        params = []
        for column, value in (
            ("scan_id", scan_id), ("severity", severity),
            ("category", category), ("fix_classification", fix_classification),
        ):
            if value is not None:
                query += f" AND {column} = ?"
                params.append(value)
        query += " ORDER BY id DESC"

        results = []
        for r in self._conn.execute(query, params).fetchall():
            sensitive = self._decrypt(r[8])
            results.append({
                "id": r[0], "scan_id": r[1], "finding_id": r[2], "rule_id": r[3],
                "category": r[4], "severity": r[5], "fix_classification": r[6],
                "detected_at": r[7], **sensitive,
            })
        return results

    def write_snapshot(self, target, snapshot_type, state, reason=None, created_at=None):
        """
        Stores one point-in-time capture of local state (e.g. one
        interface's admin_enabled/connected/mtu) before something is
        about to change it. Returns the new snapshot's id.
        """
        created_at = created_at or datetime.now(timezone.utc).isoformat()
        payload = self._encrypt({"state": state, "reason": reason})
        cur = self._conn.execute(
            "INSERT INTO snapshots (created_at, target, snapshot_type, payload) "
            "VALUES (?, ?, ?, ?)",
            (created_at, target, snapshot_type, payload),
        )
        self._conn.commit()
        return cur.lastrowid

    def get_snapshot(self, snapshot_id):
        """Direct lookup by id. Returns None if no such snapshot exists."""
        row = self._conn.execute(
            "SELECT id, created_at, target, snapshot_type, restored_at, payload "
            "FROM snapshots WHERE id = ?",
            (snapshot_id,),
        ).fetchone()
        if row is None:
            return None
        return self._snapshot_row_to_dict(row)

    def get_snapshots(self, target=None, snapshot_type=None, limit=10):
        query = (
            "SELECT id, created_at, target, snapshot_type, restored_at, payload "
            "FROM snapshots WHERE 1=1"
        )
        params = []
        for column, value in (("target", target), ("snapshot_type", snapshot_type)):
            if value is not None:
                query += f" AND {column} = ?"
                params.append(value)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        return [self._snapshot_row_to_dict(r) for r in self._conn.execute(query, params).fetchall()]

    def _snapshot_row_to_dict(self, row):
        decrypted = self._decrypt(row[5])
        return {
            "id": row[0], "created_at": row[1], "target": row[2], "snapshot_type": row[3],
            "restored_at": row[4], "state": decrypted["state"], "reason": decrypted["reason"],
        }

    def mark_snapshot_restored(self, snapshot_id, restored_at=None):
        restored_at = restored_at or datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "UPDATE snapshots SET restored_at = ? WHERE id = ?",
            (restored_at, snapshot_id),
        )
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def _selftest(db_path, key_path):
    """
    Writes a throwaway scan+finding+snapshot, reads them back, and checks
    the raw .db file bytes don't contain the plaintext -- a sanity check
    that encryption is actually happening, not a no-op.
    """
    if Path(db_path).exists() or Path(key_path).exists():
        print(f"Refusing to self-test over an existing {db_path}/{key_path} -- "
              "pass --db/--key pointing at throwaway paths.", file=sys.stderr)
        return 1

    # Two markers, deliberately: `secret_marker` only ever goes into columns
    # this file documents as encrypted, so it must never appear in the raw
    # .db bytes. `plain_marker` goes into columns documented as plaintext
    # by design (finding_id/rule_id/category/severity/fix_classification/
    # detected_at/source_version/scanned_at, and a snapshot's target/
    # snapshot_type) -- those are *supposed* to be readable in the raw
    # file, so checking for plain_marker would be testing the wrong thing.
    secret_marker = "SELFTEST-CANARY-f3a9c2"
    plain_marker = "selftest-plain-ok-to-leak"
    try:
        with A6Cache(db_path, key_path) as cache:
            scan_id = cache.write_scan(
                {"local_ip": "10.0.0.5", "gateway": "10.0.0.1", "canary": secret_marker},
                source_version="selftest",
            )
            cache.write_findings([{
                "finding_id": "selftest_finding", "rule_id": "selftest_rule",
                "category": "wifi", "severity": "info", "target": secret_marker,
                "summary": "selftest", "detail": secret_marker,
                "fix_classification": "not-fixable", "evidence": {"marker": secret_marker},
                "detected_at": datetime.now(timezone.utc).isoformat(),
            }], scan_id=scan_id)
            snapshot_id = cache.write_snapshot(
                target=plain_marker, snapshot_type="selftest",
                state={"admin_enabled": True, "marker": secret_marker}, reason=secret_marker,
            )

            scans = cache.get_scans(limit=1)
            findings = cache.get_findings(scan_id=scan_id)
            snapshot = cache.get_snapshot(snapshot_id)

        assert scans[0]["discovery"]["canary"] == secret_marker, "scan round-trip mismatch"
        assert findings[0]["target"] == secret_marker, "finding round-trip mismatch"
        assert snapshot["target"] == plain_marker, "snapshot round-trip mismatch"
        assert snapshot["reason"] == secret_marker, "snapshot reason round-trip mismatch"
        assert snapshot["state"]["marker"] == secret_marker, "snapshot state round-trip mismatch"

        raw_bytes = Path(db_path).read_bytes()
        if secret_marker.encode() in raw_bytes:
            print("FAIL: the canary string appears in plaintext inside the .db file -- "
                  "encryption is not actually protecting this data.", file=sys.stderr)
            return 1

        print("PASS: wrote+read back a scan, finding, and snapshot correctly, and the raw "
              ".db file does not contain the plaintext canary.")
        return 0
    finally:
        for p in (db_path, key_path):
            try:
                os.remove(p)
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="Offline encrypted cache (Module A6) -- stores A1 scans and A2 findings"
    )
    parser.add_argument("--db", default=DEFAULT_DB_PATH, help=f"Database file (default: {DEFAULT_DB_PATH})")
    parser.add_argument("--key", default=DEFAULT_KEY_PATH, help=f"Encryption key file (default: {DEFAULT_KEY_PATH})")
    parser.add_argument("--import-scan", metavar="PATH", help="Import an A1 --json export as a new scan")
    parser.add_argument("--source-version", default=None, help="Label to store with an imported scan, e.g. network_discovery_v0.12.0.py")
    parser.add_argument("--import-findings", metavar="PATH", help="Import an A2 --json export's findings")
    parser.add_argument("--scan-id", type=int, default=None, help="Attach --import-findings to this scan id")
    parser.add_argument("--list-scans", action="store_true", help="List recent scans")
    parser.add_argument("--list-findings", action="store_true", help="List findings")
    parser.add_argument("--list-snapshots", action="store_true", help="List snapshots")
    parser.add_argument("--severity", default=None, help="Filter --list-findings by severity")
    parser.add_argument("--category", default=None, help="Filter --list-findings by category")
    parser.add_argument("--target", default=None, help="Filter --list-snapshots by target (e.g. an interface name)")
    parser.add_argument("--limit", type=int, default=10, help="Row limit for --list-scans/--list-snapshots (default 10)")
    parser.add_argument("--selftest", action="store_true",
                         help="Run a throwaway round-trip + encryption sanity check and exit")
    args = parser.parse_args()

    if args.selftest:
        return _selftest(args.db, args.key)

    did_something = False
    try:
        with A6Cache(args.db, args.key) as cache:
            if args.import_scan:
                did_something = True
                with open(args.import_scan) as f:
                    discovery_data = json.load(f)
                scan_id = cache.write_scan(discovery_data, source_version=args.source_version)
                print(f"Imported scan from {args.import_scan} as scan id {scan_id}")

            if args.import_findings:
                did_something = True
                with open(args.import_findings) as f:
                    payload = json.load(f)
                findings = payload.get("findings", payload if isinstance(payload, list) else [])
                n = cache.write_findings(findings, scan_id=args.scan_id)
                print(f"Imported {n} finding(s) from {args.import_findings}"
                      + (f" linked to scan id {args.scan_id}" if args.scan_id else " (no scan_id given)"))

            if args.list_scans:
                did_something = True
                for s in cache.get_scans(limit=args.limit):
                    print(f"[{s['id']}] {s['scanned_at']}  source={s['source_version']}  "
                          f"local_ip={s['discovery'].get('local_ip')}  gateway={s['discovery'].get('gateway')}")

            if args.list_findings:
                did_something = True
                findings = cache.get_findings(
                    scan_id=args.scan_id, severity=args.severity, category=args.category,
                )
                if not findings:
                    print("No findings match.")
                for f in findings:
                    print(f"[{f['severity'].upper():<8}] scan={f['scan_id']} {f['category']:<10} "
                          f"{f['target']:<15} {f['summary']}")

            if args.list_snapshots:
                did_something = True
                snaps = cache.get_snapshots(target=args.target, limit=args.limit)
                if not snaps:
                    print("No snapshots match.")
                for s in snaps:
                    restored = f"restored {s['restored_at']}" if s["restored_at"] else "not restored"
                    print(f"[{s['id']}] {s['created_at']}  {s['snapshot_type']:<24} "
                          f"target={s['target']:<12} {restored}")
    except CacheError as e:
        print(f"Cache error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"File not found: {e.filename}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"Input was not valid JSON: {e}", file=sys.stderr)
        return 1

    if not did_something:
        parser.print_help()

    return 0


if __name__ == "__main__":
    sys.exit(main())
