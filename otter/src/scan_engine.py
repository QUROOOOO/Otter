"""Scan engine: run semgrep and persist findings into the otter DB.

This module locates the `semgrep` binary, executes it against a target
path using provided rule configuration, parses the JSON output and inserts
results as rows into the `vulnerabilities` table in the SQLite database
created by `otter.config`.

The implementation is conservative and defensive to handle small
variations in Semgrep's JSON structure across versions.
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple, Union

from otter.config import get_connection, DB_PATH

LOG = logging.getLogger(__name__)


class SemgrepNotFound(RuntimeError):
    pass


class ProductionScanEngine:
    """Production-grade scan engine wrapper that runs semgrep and manages database sessions."""

    def __init__(self, workspace_root: Union[str, Path], db_path: Optional[Path] = None) -> None:
        """Initialize the scan engine with a workspace root path."""
        self.workspace_root = Path(workspace_root).resolve()
        self.db_path = db_path or DB_PATH

    def run_scan(self, config_rules: Optional[str] = None) -> int:
        """Execute a security scan, log the session, and return the session_id."""
        conn = get_connection(self.db_path)
        cur = conn.cursor()
        now = datetime.utcnow().isoformat() + "Z"
        
        # Insert initial scan session
        cur.execute(
            """
            INSERT INTO scan_sessions (started_at, target_path, status, semgrep_rules)
            VALUES (?, ?, 'running', ?)
            """,
            (now, str(self.workspace_root), config_rules),
        )
        session_id = cur.lastrowid
        conn.commit()
        conn.close()

        LOG.info("Started scan session %d on target: %s", session_id, self.workspace_root)

        # Run actual Semgrep scan
        inserted_count, errors = run_semgrep_and_record(
            session_id=session_id,
            target=str(self.workspace_root),
            config=config_rules,
            db_path=self.db_path,
        )

        # Update scan session status
        conn = get_connection(self.db_path)
        cur = conn.cursor()
        finished = datetime.utcnow().isoformat() + "Z"
        status = "failed" if errors and inserted_count == 0 else "completed"
        cur.execute(
            """
            UPDATE scan_sessions
            SET finished_at = ?, status = ?
            WHERE id = ?
            """,
            (finished, status, session_id),
        )
        conn.commit()
        conn.close()

        LOG.info("Finished scan session %d with status: %s", session_id, status)
        return session_id


# ... (rest of the file content remains unchanged, but we modify __all__ at the end)



def _find_semgrep_executable() -> str:
    exe = shutil.which("semgrep")
    if not exe:
        raise SemgrepNotFound("semgrep binary not found in PATH; install semgrep")
    return exe


def _build_semgrep_cmd(semgrep_exe: str, target: str, config: Optional[str] = None) -> List[str]:
    # Use explicit list form so subprocess does not invoke the shell.
    cmd = [semgrep_exe, "--json", "--no-git-ignore", str(target)]
    if config:
        # semgrep accepts --config <path|registry> (can be a directory or file)
        # put it before the target so semgrep picks it up
        cmd = [semgrep_exe, "--json", "--no-git-ignore", "--config", str(config), str(target)]
    return cmd


def _parse_semgrep_json(payload: dict) -> List[dict]:
    """Normalize semgrep JSON payload into a list of result dicts.

    Semgrep historically returns an object with a `results` key containing a
    list of result dicts. Some versions may produce a top-level list.
    This helper returns a list (possibly empty) of result dicts.
    """
    if payload is None:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        # Typical structure: {"results": [...], ...}
        results = payload.get("results")
        if isinstance(results, list):
            return results
        # Some versions may nest differently: try to find keys that look like results
        for k in ("matches", "alerts"):
            v = payload.get(k)
            if isinstance(v, list):
                return v
    return []


def _extract_coordinates(result: dict) -> Tuple[Optional[int], Optional[int], Optional[int], Optional[int]]:
    # Semgrep places start/end in different spots depending on version. Handle both.
    start_line = end_line = start_col = end_col = None
    # explicit keys
    if "start" in result and isinstance(result.get("start"), dict):
        start_line = result["start"].get("line")
        start_col = result["start"].get("col")
    if "end" in result and isinstance(result.get("end"), dict):
        end_line = result["end"].get("line")
        end_col = result["end"].get("col")

    # older semgrep: `extra` container
    extra = result.get("extra") or {}
    if not start_line and isinstance(extra.get("start"), dict):
        start_line = extra["start"].get("line")
        start_col = extra["start"].get("col")
    if not end_line and isinstance(extra.get("end"), dict):
        end_line = extra["end"].get("line")
        end_col = extra["end"].get("col")

    return start_line, end_line, start_col, end_col


def _extract_path(result: dict) -> Optional[str]:
    # semgrep may provide a simple path string or a dict
    path = result.get("path")
    if isinstance(path, dict):
        # newer: {"path": {"text": "file.py"}}
        p = path.get("text") or path.get("value")
        return p
    if isinstance(path, str):
        return path
    # sometimes in extra
    extra = result.get("extra") or {}
    p = extra.get("path") or extra.get("filepath")
    if isinstance(p, str):
        return p
    return None


def _normalize_result(result: dict) -> dict:
    """Return a normalized dict with fields matching our DB schema."""
    start_line, end_line, start_col, end_col = _extract_coordinates(result)
    file_path = _extract_path(result)
    rule_id = result.get("check_id") or result.get("rule_id") or (result.get("extra") or {}).get("id")
    message = (result.get("extra") or {}).get("message") or result.get("message") or ""
    severity = (result.get("extra") or {}).get("severity") or result.get("severity")
    return {
        "rule_id": rule_id,
        "message": message,
        "file_path": file_path,
        "start_line": start_line,
        "end_line": end_line,
        "start_col": start_col,
        "end_col": end_col,
        "severity": severity,
    }


def run_semgrep_and_record(
    session_id: int,
    target: str,
    config: Optional[str] = None,
    db_path: Optional[Path] = None,
    timeout: int = 300,
) -> Tuple[int, List[str]]:
    """Run semgrep against `target` and insert results into the DB.

    Returns tuple (inserted_count, errors).
    """
    errors: List[str] = []
    try:
        semgrep_exe = _find_semgrep_executable()
    except SemgrepNotFound as exc:
        errors.append(str(exc))
        LOG.error("%s", exc)
        return 0, errors

    cmd = _build_semgrep_cmd(semgrep_exe, target, config)
    LOG.debug("Running semgrep: %s", cmd)

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        msg = f"semgrep timed out after {timeout}s"
        LOG.error(msg)
        errors.append(msg)
        return 0, errors

    out = proc.stdout.strip() or proc.stderr.strip()
    if not out:
        LOG.debug("semgrep produced no output; returncode=%s stderr=%s", proc.returncode, proc.stderr)
        if proc.returncode != 0:
            errors.append(f"semgrep failed: returncode={proc.returncode} stderr={proc.stderr.strip()}")
        return 0, errors

    try:
        payload = json.loads(out)
    except Exception as exc:  # pragma: no cover - defensive
        LOG.exception("Failed to decode semgrep JSON output")
        errors.append(f"Failed to decode semgrep JSON: {exc}")
        return 0, errors

    results = _parse_semgrep_json(payload)
    if not results:
        LOG.debug("No results from semgrep payload")

    rows = []
    now = datetime.utcnow().isoformat() + "Z"
    for r in results:
        norm = _normalize_result(r)
        # Ensure file_path is a string if possible
        fp = norm.get("file_path")
        if fp:
            fp = str(Path(fp))
        rows.append(
            (
                session_id,
                "semgrep",
                norm.get("rule_id"),
                norm.get("message"),
                fp,
                norm.get("start_line"),
                norm.get("end_line"),
                norm.get("start_col"),
                norm.get("end_col"),
                norm.get("severity"),
                "open",
                now,
            )
        )

    if not rows:
        return 0, errors

    # Insert batch into DB
    conn = get_connection(db_path or DB_PATH)
    inserted = 0
    try:
        cur = conn.cursor()
        cur.executemany(
            """
            INSERT INTO vulnerabilities (
                session_id, tool, rule_id, message, file_path,
                start_line, end_line, start_col, end_col,
                severity, remediation_status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
        inserted = cur.rowcount if cur.rowcount is not None else len(rows)
        conn.commit()
        LOG.info("Inserted %d semgrep findings for session %s", inserted, session_id)
    except Exception:
        LOG.exception("Failed to insert semgrep results into DB")
        errors.append("DB insertion error")
        conn.rollback()
    finally:
        conn.close()

    return inserted, errors


__all__ = ["run_semgrep_and_record", "ProductionScanEngine"]
