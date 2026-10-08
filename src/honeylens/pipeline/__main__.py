"""Allow ``python -m honeylens.pipeline``."""

import sys

from honeylens.pipeline.runner import main

sys.exit(main())
