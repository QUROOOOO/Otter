"""Otter: Automated Security Vulnerability Remediation Tool.

This is the main entry point that orchestrates scanning, remediation, and MR submission.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import List

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from openinference.instrumentation import using_metadata

from otter.config import get_connection, DB_PATH
from otter.src.scan_engine import ProductionScanEngine
from otter.src.patch_agent import ProductionPatchAgent
from otter.src.gitlab_client import GitLabAutomationClient

# Setup basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
LOG = logging.getLogger("otter.main")

# Auto-instrument raw requests calls (Gemini API calls)
try:
    RequestsInstrumentor().instrument()
    LOG.info("Successfully instrumented requests module for telemetry tracking.")
except Exception as e:
    LOG.warning("Failed to instrument requests module: %s", e)

# Initialize OpenTelemetry tracer pointing to the local Phoenix collector endpoint
# Phoenix OTLP HTTP trace collector endpoint is http://localhost:6006/v1/traces
resource = Resource(attributes={"service.name": "otter-patch-service"})
provider = TracerProvider(resource=resource)
exporter = OTLPSpanExporter(endpoint="http://localhost:6006/v1/traces")
processor = BatchSpanProcessor(exporter)
provider.add_span_processor(processor)
trace.set_tracer_provider(provider)

tracer = trace.get_tracer("otter.tracer")


def main() -> None:
    """Orchestrate the entire end-to-end patching pipeline."""
    # Determine the target workspace root
    if len(sys.argv) > 1:
        workspace_root = Path(sys.argv[1]).resolve()
    else:
        workspace_root = Path.cwd()

    LOG.info("Initializing Otter Pipeline on workspace root: %s", workspace_root)

    # Step 1: Initialize ProductionScanEngine, execute security scan, and retrieve the session_id
    scan_engine = ProductionScanEngine(workspace_root)
    rules_config = "rules" if (workspace_root / "rules").is_dir() else None
    session_id = scan_engine.run_scan(rules_config)
    session_id_str = str(session_id)
    LOG.info("Scan execution complete. Session ID: %s", session_id_str)

    # Step 2: Query SQLite database to fetch all pending rows matching this session_id.
    conn = get_connection()
    cur = conn.cursor()
    # Query for open vulnerabilities matching the current session ID
    cur.execute(
        """
        SELECT id, file_path, rule_id, message, start_line, remediation_status
        FROM vulnerabilities
        WHERE session_id = ? AND remediation_status = 'open'
        """,
        (session_id,)
    )
    rows = cur.fetchall()
    conn.close()

    finding_count = len(rows)
    LOG.info("Query returned %d pending vulnerabilities.", finding_count)

    # Step 3: Wrap the loop inside a single OpenTelemetry root span named "otter.execution".
    # Set root attributes for target repo path and finding count.
    with tracer.start_as_current_span("otter.execution") as root_span:
        root_span.set_attribute("target.repo_path", str(workspace_root))
        root_span.set_attribute("finding.count", finding_count)

        if finding_count == 0:
            LOG.info("No pending vulnerabilities to remediate.")
            return

        # Initialize Patch Agent and GitLab Automation Client
        try:
            patch_agent = ProductionPatchAgent(workspace_root)
        except ValueError as val_err:
            LOG.error("Failed to initialize Patch Agent: %s", val_err)
            root_span.record_exception(val_err)
            root_span.set_status(trace.StatusCode.ERROR, str(val_err))
            return

        gitlab_client = None
        try:
            gitlab_client = GitLabAutomationClient()
        except Exception as git_err:
            LOG.warning(
                "GitLabAutomationClient initialization skipped or failed: %s. "
                "Remediations will run locally but MRs will not be submitted.",
                git_err
            )

        # Use openinference-instrumentation context wrapper to track LLM session telemetry
        with using_metadata({"session_id": session_id_str}):
            for row in rows:
                row_id = row["id"]
                file_path_abs = row["file_path"]
                vulnerability_type = row["rule_id"] or "Unknown Vulnerability"
                line_number = row["start_line"] or 1

                # Calculate relative path
                try:
                    file_path_rel = str(Path(file_path_abs).relative_to(workspace_root))
                except ValueError:
                    file_path_rel = file_path_abs

                LOG.info(
                    "Remediating row ID %d: %s at %s:%d",
                    row_id, vulnerability_type, file_path_rel, line_number
                )

                # Open a nested child span: "remediation_step"
                # Attach attributes: 'reasoning.vulnerability_type', 'reasoning.patch_strategy' = "minimal_syntax_fix", and 'target.file_path'.
                with tracer.start_as_current_span("remediation_step") as child_span:
                    child_span.set_attribute("reasoning.vulnerability_type", vulnerability_type)
                    child_span.set_attribute("reasoning.patch_strategy", "minimal_syntax_fix")
                    child_span.set_attribute("target.file_path", file_path_rel)

                    # Call ProductionPatchAgent.remediate_vulnerability()
                    success = patch_agent.remediate_vulnerability(
                        file_path_rel=file_path_rel,
                        vulnerability_type=vulnerability_type,
                        line_number=line_number,
                    )

                    if success:
                        LOG.info("Remediation succeeded for row %d", row_id)
                        
                        # Read the patched content
                        patched_content = (workspace_root / file_path_rel).read_text(encoding="utf-8")
                        mr_url = None

                        if gitlab_client:
                            # Open another nested span "submit_mr"
                            with tracer.start_as_current_span("submit_mr") as mr_span:
                                try:
                                    # Construct Trace URL for Arize Phoenix
                                    trace_id = child_span.get_span_context().trace_id
                                    trace_id_hex = format(trace_id, "032x")
                                    trace_url = f"http://localhost:6006/projects/1/traces/{trace_id_hex}"
                                    mr_span.set_attribute("phoenix.trace_url", trace_url)

                                    # Call GitLab client to push code and create MR
                                    mr_url = gitlab_client.create_merge_request(
                                        file_path_rel=file_path_rel,
                                        patched_content=patched_content,
                                        vulnerability_type=vulnerability_type,
                                        iterations=patch_agent.last_iterations,
                                        trace_url=trace_url,
                                    )
                                    mr_span.set_attribute("gitlab.mr_url", mr_url)
                                    LOG.info("Merge Request created: %s", mr_url)
                                except Exception as mr_ex:
                                    LOG.error("Failed to submit Merge Request to GitLab: %s", mr_ex)
                                    mr_span.record_exception(mr_ex)
                                    mr_span.set_status(trace.StatusCode.ERROR, str(mr_ex))
                        else:
                            LOG.info("Skipping GitLab Merge Request submission (GitLabAutomationClient not configured)")

                        # Flag the database row status as 'RESOLVED'
                        db_status = "RESOLVED"
                        conn_db = get_connection()
                        cur_db = conn_db.cursor()
                        cur_db.execute(
                            "UPDATE vulnerabilities SET remediation_status = ? WHERE id = ?",
                            (db_status, row_id)
                        )
                        conn_db.commit()
                        conn_db.close()
                        LOG.info("Database row ID %d updated to RESOLVED.", row_id)

                    else:
                        # Log failure tracking to the telemetry span metrics
                        LOG.error("Remediation failed for row %d", row_id)
                        child_span.set_status(trace.StatusCode.ERROR, "Remediation failed")
                        child_span.set_attribute("remediation.error", "AI patching failed or syntax checks failed")

                        # Mark the database row status as 'FAILED'
                        db_status = "FAILED"
                        conn_db = get_connection()
                        cur_db = conn_db.cursor()
                        cur_db.execute(
                            "UPDATE vulnerabilities SET remediation_status = ? WHERE id = ?",
                            (db_status, row_id)
                        )
                        conn_db.commit()
                        conn_db.close()
                        LOG.info("Database row ID %d updated to FAILED.", row_id)


if __name__ == "__main__":
    main()
