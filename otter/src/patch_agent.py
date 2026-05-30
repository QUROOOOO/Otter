"""Patch Agent implementation.

This module contains the ProductionPatchAgent class, which uses the Gemini API
to autonomously generate security fixes for vulnerabilities in Python files,
and verifies them using the MicroSandbox.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import requests
from typing import Union

from otter.src.sandbox_manager import MicroSandbox

LOG = logging.getLogger(__name__)


class ProductionPatchAgent:
    """Production-grade patch agent that uses Gemini API to remediate code vulnerabilities."""

    def __init__(self, workspace_root: Union[str, Path]) -> None:
        """Initialize the ProductionPatchAgent.

        Pulls the GEMINI_API_KEY directly from environment variables.
        """
        self.workspace_root = Path(workspace_root).resolve()
        self.api_key = os.environ.get("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable is not set")

        # Instantiate the MicroSandbox
        self.sandbox = MicroSandbox(self.workspace_root)
        self.last_iterations = 0

    def _strip_markdown(self, content: str) -> str:
        """Clean markdown formatting and backticks from the model output."""
        content = content.strip()
        # Check for ```python or ``` at the beginning
        if content.startswith("```python"):
            content = content[9:].lstrip()
        elif content.startswith("```"):
            content = content[3:].lstrip()

        # Check for ``` at the end
        if content.endswith("```"):
            content = content[:-3].rstrip()

        return content

    def _call_gemini(self, prompt: str) -> str:
        """Call the Gemini API with the given prompt and return the text output."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ]
        }

        response = requests.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()

        res_json = response.json()
        try:
            generated_text = res_json["candidates"][0]["content"]["parts"][0]["text"]
            return self._strip_markdown(generated_text)
        except (KeyError, IndexError) as e:
            LOG.error("Failed to parse Gemini API response: %s. Response data: %s", e, res_json)
            raise RuntimeError(f"Unexpected Gemini API response structure: {res_json}") from e

    def remediate_vulnerability(
        self, file_path_rel: str, vulnerability_type: str, line_number: int
    ) -> bool:
        """Remediate a vulnerability in a file using a 3-turn self-correction loop.

        Args:
            file_path_rel: The relative path to the target file.
            vulnerability_type: The type of vulnerability (e.g., 'SQL Injection').
            line_number: The line number where the vulnerability was detected.

        Returns:
            True if remediated and verified successfully, False otherwise.
        """
        self.last_iterations = 0
        target_path = self.workspace_root / file_path_rel
        if not target_path.exists():
            LOG.error("Target file does not exist: %s", target_path)
            return False

        # Keep backup of original content to revert if needed or to check syntax
        original_content = target_path.read_text(encoding="utf-8")

        # Initial prompt generation
        prompt = (
            f"You are an expert security patch developer.\n"
            f"Your task is to fix a security vulnerability of type '{vulnerability_type}' on or near line {line_number} of the following Python file.\n\n"
            f"Here is the current content of the file:\n"
            f"---UNTRUSTED_CODE_START---\n"
            f"{original_content}\n"
            f"---UNTRUSTED_CODE_END---\n\n"
            f"Please output ONLY the complete, raw updated file content. Do not include any markdown syntax, code block formatting (such as ```python), explanations, or conversational text. The output must be valid Python code that is ready to run.\n"
        )

        last_patched_content = ""

        # 3-Turn Autonomous Self-Correction Loop
        for turn in range(1, 4):
            self.last_iterations = turn
            LOG.info("Turn %d: Attempting remediation for %s", turn, file_path_rel)
            try:
                # Generate patch
                last_patched_content = self._call_gemini(prompt)

                # Pass content to MicroSandbox for validation
                success, error_message = self.sandbox.verify_patch_syntax(
                    file_path_rel, last_patched_content
                )

                if success:
                    # Overwrite the target file and return True
                    LOG.info("Syntax check passed on turn %d for %s. Applying patch.", turn, file_path_rel)
                    target_path.write_text(last_patched_content, encoding="utf-8")
                    return True

                # If verification returns syntax errors: capture logs and build a correction prompt
                LOG.warning("Syntax check failed on turn %d for %s: %s", turn, file_path_rel, error_message)
                prompt = (
                    f"You are an expert security patch developer.\n"
                    f"We tried applying your proposed patch, but it caused a Python syntax compilation error.\n\n"
                    f"Here is the error output we received from py_compile:\n"
                    f"{error_message}\n\n"
                    f"Here is the code you generated:\n"
                    f"---UNTRUSTED_CODE_START---\n"
                    f"{last_patched_content}\n"
                    f"---UNTRUSTED_CODE_END---\n\n"
                    f"Please fix the syntax error and any other issues, and output ONLY the complete, raw corrected file content. Do not include any markdown syntax, code block formatting, explanations, or conversational text. The output must be valid Python code that compiles successfully.\n"
                )

            except Exception as e:
                LOG.error("Error during turn %d of self-correction loop: %s", turn, e)
                # In case of exception, we continue the loop or fail if last turn
                if turn == 3:
                    break

        # Discard changes (by not writing) and return False
        LOG.error("Failed to remediate vulnerability in %s after 3 turns", file_path_rel)
        return False

