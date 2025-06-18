## Setup

# Create and activate virtual environment
`python3 -m venv .venv && source .venv/bin/activate`

# Install project in editable mode (includes all dependencies)
`pip install -e .`

# Install dev dependencies
`pip install -e ".[dev]"`

# Start the application
`uvicorn app:app --reload`