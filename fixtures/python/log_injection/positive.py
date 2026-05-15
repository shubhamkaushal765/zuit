"""Positive fixtures for SEC015-log-injection (CWE-117)."""

import logging

logger = logging.getLogger(__name__)


# Case 1: logger.info with format placeholder + request param
def view(req):
    logger.info("user said {}".format(req.body))


# Case 2: logger.info with printf-style placeholder + request param
def handle(req):
    logger.info("user: %s", req.body)


# Case 3: logger.warning with request-style identifier
def process(request):
    logger.warning("processing: %s", request)


# Case 4: logging.debug with input identifier
def run(user_input):
    logging.debug("received: %s", user_input)
