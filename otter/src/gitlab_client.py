"""GitLab Automation Client.

This module provides the GitLabAutomationClient class, which interacts with the GitLab API
using the python-gitlab library to automate repository branching, committing patches,
and submitting merge requests for security vulnerability remediation.
"""

from __future__ import annotations

import logging
import os
import uuid
import gitlab
from typing import Dict, Any

LOG = logging.getLogger(__name__)


class GitLabAutomationClient:
    """Production-grade client to automate code submission and MR creation on GitLab."""

    def __init__(self) -> None:
        """Initialize the GitLab client using environment variables.

        Loads GITLAB_TOKEN and GITLAB_PROJECT_ID directly from environment variables.
        """
        self.token = os.environ.get("GITLAB_TOKEN")
        self.project_id = os.environ.get("GITLAB_PROJECT_ID")

        if not self.token:
            raise ValueError("GITLAB_TOKEN environment variable is not set")
        if not self.project_id:
            raise ValueError("GITLAB_PROJECT_ID environment variable is not set")

        try:
            self.gl = gitlab.Gitlab("https://gitlab.com", private_token=self.token)
            # Authenticate to verify the token is valid
            self.gl.auth()
            self.project = self.gl.projects.get(self.project_id)
            LOG.info("Successfully connected to GitLab project: %s", self.project.path_with_namespace)
        except Exception as e:
            LOG.error("Failed to initialize GitLab client or fetch project: %s", e)
            raise RuntimeError(f"GitLab connection failed: {e}") from e

    def create_merge_request(
        self,
        file_path_rel: str,
        patched_content: str,
        vulnerability_type: str,
        iterations: int,
        trace_url: str,
    ) -> str:
        """Create a distinct branch, commit the patched content, and submit a clean Merge Request.

        Args:
            file_path_rel: The relative path of the file containing the vulnerability.
            patched_content: The verified patched file content to commit.
            vulnerability_type: The type of security vulnerability resolved.
            iterations: The number of turns/iterations it took to self-correct.
            trace_url: Hyperlink to the active Arize Phoenix Trace URL.

        Returns:
            The web URL of the created Merge Request.
        """
        # Generate a distinct unique branch name
        branch_name = f"otter-patch-{uuid.uuid4().hex[:8]}"
        LOG.info("Creating branch '%s' off 'main' for MR...", branch_name)

        try:
            # Provision this branch off the repository 'main' reference
            self.project.branches.create({"branch": branch_name, "ref": "main"})
            LOG.debug("Branch '%s' provisioned successfully.", branch_name)

            # Create commit update action passing the relative file path and updated file string
            commit_data = {
                "branch": branch_name,
                "commit_message": f"Security Patch: Resolve {vulnerability_type} in {file_path_rel}",
                "actions": [
                    {
                        "action": "update",
                        "file_path": file_path_rel,
                        "content": patched_content,
                    }
                ],
            }
            self.project.commits.create(commit_data)
            LOG.debug("Committed security patch to branch '%s'.", branch_name)

            # Create and submit a clean Merge Request targeting the 'main' branch
            mr_title = f"Remediate security vulnerability: {vulnerability_type} in {file_path_rel}"
            
            mr_description = (
                "### Otter Auto-Remediation Summary\n\n"
                f"- **Target File**: `{file_path_rel}`\n"
                f"- **Vulnerability Type**: `{vulnerability_type}`\n"
                f"- **Repair Iteration Count**: `{iterations}`\n"
                f"- **Arize Phoenix Trace Link**: [Telemetry Trace Link]({trace_url})\n\n"
                "*This merge request was generated automatically by the Otter security patching daemon.*"
            )

            mr_payload = {
                "source_branch": branch_name,
                "target_branch": "main",
                "title": mr_title,
                "description": mr_description,
            }
            
            mr = self.project.mergerequests.create(mr_payload)
            LOG.info("Successfully created Merge Request: %s", mr.web_url)
            return mr.web_url

        except Exception as e:
            LOG.error("GitLab operations failed: %s", e)
            raise RuntimeError(f"Failed to submit security patch to GitLab: {e}") from e
