import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Some sandboxes for this project pre-install a Chromium build outside
# Playwright's usual managed location instead of running
# `playwright install`. Point at it when present; CI (which does run
# `playwright install --with-deps chromium`) doesn't have this path, so
# it falls through to pytest-playwright's own default there.
_LOCAL_CHROMIUM = "/opt/pw-browsers/chromium"

if os.path.exists(_LOCAL_CHROMIUM):
    @pytest.fixture(scope="session")
    def browser_type_launch_args(browser_type_launch_args):
        return {**browser_type_launch_args, "executable_path": _LOCAL_CHROMIUM}
