#!/bin/bash
set -e

echo "Checking for uv..."
if ! command -v uv &>/dev/null; then
  echo "uv not found. Installing uv..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  echo "Please restart your shell or source $HOME/.cargo/env"
  exit 1
fi

echo "Creating virtual environment..."
uv venv .venv

echo "Installing dependencies..."
uv pip install -e ".[dev]" --python .venv/bin/python

echo "Setup complete. To activate the environment, run:"
echo "Rin source .venv/bin/activate"
