# Fixture: MAINT011-active-debug-code — Python negative cases
# None of these should produce a MAINT011 finding.

import logging

logger = logging.getLogger(__name__)


def process_data(data):
    logger.info("Processing data")
    return data


def handle_error(err):
    logger.error("Error occurred: %s", err)


# print inside __main__ guard — not flagged
if __name__ == "__main__":
    print("Running in development mode")
