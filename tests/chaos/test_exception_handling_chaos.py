# This file was intentionally retired when the Python proxy (src/security/pipeline.py,
# src/security/models.py) was deleted in Phase 15.  The chaos scenarios it covered
# (simultaneous Redis + external-service failures) are now exercised by the Go proxy
# chaos suite in tests/chaos/test_go_proxy_chaos.py and the integration suite.
#
# The file is kept as an empty placeholder to avoid git history disruption.
# It contains no test functions, so pytest collects nothing from it.
