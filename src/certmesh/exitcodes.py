"""
certmesh.exitcodes
==================

Structured exit codes for the certmesh CLI.

Exit codes:
    0 -- Success
    1 -- Configuration or authentication error
    2 -- Certificate operation error (provider API failure, validation, etc.)
    3 -- Unexpected / unhandled error
"""

EXIT_SUCCESS = 0
EXIT_CONFIG_AUTH_ERROR = 1
EXIT_CERT_OPERATION_ERROR = 2
EXIT_UNEXPECTED_ERROR = 3
