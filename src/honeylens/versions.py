"""Versions of the upstream software HoneyLens is built and tested against.

Single source of truth inside the Python package (the report methodology
section quotes it). ``docker-compose.yml`` pins the actual images; the test
``tests/test_versions.py`` fails when the two disagree, so a Dependabot bump
of the Cowrie image cannot silently leave the report claiming an old version.
"""

COWRIE_VERSION = "3.1.1"
