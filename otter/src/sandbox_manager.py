"""Sandbox manager for syntax validation.

This module provides the MicroSandbox class to perform safe, isolated syntax checks on proposed
Python code patches using py_compile in a secure subprocess.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path
from typing import Tuple, Union

LOG = logging.getLogger(__name__)


class MicroSandbox:
    """A minimal sandbox to verify syntax of proposed patches before application."""

    def __init__(self, workspace_root: Union[str, Path]) -> None:
        """Initialize the MicroSandbox with the workspace root path."""
        self.workspace_root = Path(workspace_root).resolve()

    def verify_patch_syntax(self, target_file_rel: str, patched_content: str) -> Tuple[bool, str]:
        """Verify the Python syntax of the patched content.

        Creates an isolated temporary directory at '/tmp/sf_sandbox/' if it does not exist,
        writes the patched content into a temporary file corresponding to the target file's name,
        runs `python3 -m py_compile` to check for syntax errors, and cleans up the temporary file.

        Args:
            target_file_rel: Relative path of the target file to be patched.
            patched_content: The proposed patched content as a string.

        Returns:
            A tuple (success, error_message). success is True if the compilation exit code
            is 0 (syntax valid), and False otherwise. error_message contains stderr output if failed.
        """
        sandbox_dir = Path("/tmp/sf_sandbox")
        sandbox_dir.mkdir(parents=True, exist_ok=True)

        # Determine the target file's name and its temporary path inside the sandbox
        temp_file_path = sandbox_dir / Path(target_file_rel).name

        try:
            # Write the patched content to the temporary file
            temp_file_path.write_text(patched_content, encoding="utf-8")

            # Secure subprocess array using python3 for py_compile syntax checking
            cmd = ["python3", "-m", "py_compile", str(temp_file_path)]

            try:
                # Execute the syntax check with a hard timeout of 10 seconds
                # and shell=False to prevent command injection.
                result = subprocess.run(
                    cmd,
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                )
                # On Windows, if python3 is not installed, the app execution alias
                # runs and exits with 9009. We treat this as FileNotFoundError to fallback.
                if result.returncode == 9009:
                    raise FileNotFoundError("python3 is a Windows App Store alias placeholder")
            except FileNotFoundError:
                # Fallback for environments (like Windows) where 'python3' is not in PATH
                # but 'python' or the current sys.executable is available.
                fallback_exe = sys.executable or "python"
                LOG.debug("python3 not found. Falling back to %s", fallback_exe)
                cmd[0] = fallback_exe
                result = subprocess.run(
                    cmd,
                    shell=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                )

            # Return (True, "") if compilation exit code is 0, (False, stderr) otherwise
            if result.returncode == 0:
                return True, ""
            else:
                return False, result.stderr.decode("utf-8")

        except subprocess.TimeoutExpired as e:
            LOG.warning("Syntax verification timed out for %s", target_file_rel)
            return False, f"TimeoutExpired: {e}"
        except Exception as e:
            LOG.error("Failed to verify patch syntax for %s: %s", target_file_rel, e)
            return False, str(e)
        finally:
            # Wrap the file execution in a strict try/finally block ensuring
            # that the temporary file inside '/tmp/sf_sandbox/' is completely deleted
            if temp_file_path.exists():
                try:
                    temp_file_path.unlink()
                except Exception as e:
                    LOG.error("Failed to delete temporary file %s: %s", temp_file_path, e)
