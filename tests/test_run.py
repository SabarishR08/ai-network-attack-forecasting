"""Tests for run.py entry point."""

import subprocess
import sys
from pathlib import Path


class TestRunPy:
    """Test the main entry point."""

    def test_run_py_imports_cleanly(self):
        """Verify run.py can be imported without errors."""
        result = subprocess.run(
            [sys.executable, "-c", "import run"],
            cwd=str(Path(__file__).parent.parent),
            capture_output=True,
            text=True,
            timeout=10,
        )
        # The import should succeed (it only runs main on __name__ == "__main__")
        assert result.returncode == 0

    def test_run_py_help(self):
        """Verify --help flag works."""
        result = subprocess.run(
            [sys.executable, "run.py", "--help"],
            cwd=str(Path(__file__).parent.parent),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        assert "SIH26153" in result.stdout

    def test_run_py_pipeline_only_flag(self):
        """Verify --pipeline-only flag is accepted."""
        result = subprocess.run(
            [sys.executable, "run.py", "--help"],
            cwd=str(Path(__file__).parent.parent),
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert "--pipeline-only" in result.stdout
        assert "--no-pipeline" in result.stdout
        assert "--reuse-data" in result.stdout
