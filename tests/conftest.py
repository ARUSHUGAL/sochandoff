"""Point HOME at a throwaway folder BEFORE sochandoff is imported, so tests
never read or write the real ~/.sochandoff (memory, feeds, audit, redact map)."""

import os
import tempfile

os.environ["HOME"] = tempfile.mkdtemp(prefix="sochandoff-test-home-")
os.environ.pop("SOCHANDOFF_CA_FILE", None)
