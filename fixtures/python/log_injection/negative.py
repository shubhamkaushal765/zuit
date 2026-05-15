"""Negative fixtures for SEC015-log-injection (CWE-117).

None of these should trigger a finding.
"""

import logging

logger = logging.getLogger(__name__)


# No placeholder, no user-input arg
def startup():
    logger.info("startup complete")


# Placeholder but non-request, non-param arg
def report(total):
    logger.info("user count: %d", total)


# Not a logging function
def process(req):
    print("processing", req)


# Logging with a safe static string
def log_version():
    logger.debug("version 1.0.0")
