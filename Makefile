.PHONY: test lint format-check quality help version

test:
	python -m pytest

lint:
	python -m ruff check .

format-check:
	python -m ruff format --check .

quality: test lint format-check

help:
	python -m triage_lab --help

version:
	python -m triage_lab --version
