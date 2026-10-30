"""Shared pytest fixtures."""

import pytest


@pytest.fixture(autouse=True)
def isolated_event_log(tmp_path, monkeypatch):
    """Every test writes incidents to a throwaway file, never to
    backend/event_log.jsonl (which feeds the Analytics page)."""
    monkeypatch.setenv("SGIDS_EVENT_LOG", str(tmp_path / "event_log.jsonl"))
