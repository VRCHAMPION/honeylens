"""HoneyLens: an SSH honeypot + threat-intelligence pipeline for learning.

The package is split into small sub-packages, one per job:

* ``honeylens.pipeline``  - read Cowrie JSON logs, clean them, store them
* ``honeylens.enrich``    - add country / network (ASN) information to IPs
* ``honeylens.mitre``     - map attacker commands to MITRE ATT&CK techniques
* ``honeylens.reporting`` - weekly HTML report and IOC (Indicator of Compromise) exports
* ``honeylens.simulator`` - safe, local-only fake attackers for demos and tests
"""

__version__ = "1.0.0"
