import os

# Set by the image build from the release tag, "dev" when running locally
__version__ = os.environ.get("SHERLOCK_VERSION", "dev")
