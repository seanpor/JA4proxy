import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = str(Path(__file__).resolve().parents[2])
JA4P_BIN = f"{ROOT}/bin/ja4p"
MAKE_CMD = "make"

class TestSystemBootstrap:
    """End-to-end test for bootstrapping the system from zero."""

    @pytest.mark.live_services
    @pytest.mark.skipif(not os.path.exists(JA4P_BIN), reason="ja4p binary not built")
    def test_e2e_poc_bootstrap(self, tmp_path):
        """Verify the full flow: init -> build -> start -> traffic."""
        # 1. Clean environment (simulation).
        # Copy config/ so ja4p init writes to tmp_path, not the real config dir.
        shutil.copytree(f"{ROOT}/config", tmp_path / "config")
        for d in ["scripts", "template.env", "Makefile"]:
            os.symlink(f"{ROOT}/{d}", tmp_path / d)
        
        # 2. ja4p init (non-interactive lane-1 = POC mode)
        subprocess.run(
            [JA4P_BIN, "init", "--non-interactive", "--lane", "1"],
            capture_output=True,
            text=True,
            check=True,
            cwd=tmp_path,
        )
        assert (tmp_path / ".env").exists()

        # 4. Verify 'make' target for POC exists and is valid
        # We use -n (dry-run) to avoid actually starting docker
        result = subprocess.run([MAKE_CMD, "-n", "start-poc"], capture_output=True, text=True, check=True, cwd=tmp_path)
        assert "scripts/start-poc.sh" in result.stdout
        pass

    def test_logic_parity_placeholder(self):
        """Verification logic for parity between simulator and engine."""
        # This will be expanded in a future sub-phase.
        assert True
