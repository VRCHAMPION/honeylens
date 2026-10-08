# cowrie/ - honeypot configuration

* `cowrie.cfg` - our overrides of Cowrie's defaults (each line explains why).
* `userdb.txt` - the FAKE passwords that let attackers "log in". Only these exact pairs work;
  there is no wildcard, so every other username/password fails:

  | Username | Password | Why it is on the list |
  |---|---|---|
  | root | admin123 | common weak root password |
  | root | xc3511 | Mirai botnet default (IoT) |
  | admin | admin | router/IoT default |
  | ubuntu | ubuntu | cloud image default |
  | pi | raspberry | old Raspberry Pi default |

  Checked with Cowrie's own `UserDB` class: `scripts/check_cowrie_userdb.py` and `tests/test_cowrie_userdb.py`.
* `honeyfs/` - realistic file contents (`/etc/issue`, `/etc/motd`, `/etc/os-release`, `/etc/hostname`)
  shown when an attacker runs `cat`.

All three are mounted READ-ONLY into the container. Nothing here is a real secret.
