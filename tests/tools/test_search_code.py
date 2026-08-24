"""search_code reports file:line, stays in the tree, and cannot be hung."""

from __future__ import annotations

import time

import pytest

from aisec.tools import MAX_MATCHES, MAX_PATTERN_CHARS, Sandbox, search_code


@pytest.fixture
def sandbox(source_root):
    box = Sandbox.for_target(source_root, "http://127.0.0.1:1")
    try:
        yield box
    finally:
        box.close()


def test_matches_are_reported_with_file_and_line(sandbox):
    result = search_code(sandbox, r"def download\(")

    assert result.ok
    assert result.meta["matches"] == 1
    assert "routes/attachments.py:17: def download():" in result.content


def test_an_invalid_regex_is_an_error_not_an_exception(sandbox):
    for pattern in ("(", "[a-", "*", "(?P<x>a)(?P<x>b)"):
        result = search_code(sandbox, pattern)
        assert result.ok is False, pattern
        assert "invalid regular expression" in result.error


def test_an_oversized_pattern_is_refused(sandbox):
    result = search_code(sandbox, "a" * (MAX_PATTERN_CHARS + 1))

    assert result.ok is False
    assert "cap" in result.error


def test_a_catastrophic_pattern_completes_because_matching_is_per_line(sandbox):
    # Matching per line bounds backtracking by the longest line in the tree
    # (~120 chars) instead of by file size. A wall-clock budget could not
    # substitute: `re` is not interruptible from the calling thread, so the
    # check would only run once the hang was already over.
    started = time.monotonic()
    result = search_code(sandbox, r"(a+)+$", glob="*")
    elapsed = time.monotonic() - started

    assert result.ok
    assert elapsed < 2.0, f"took {elapsed:.2f}s"


def test_the_scan_is_confined_to_the_source_root(sandbox):
    # "The one rule" lives in the repo's CLAUDE.md, one level above the target.
    result = search_code(sandbox, "The model never renders a verdict", glob="*.md")

    assert result.ok
    assert result.meta["matches"] == 0


def test_the_private_directory_is_never_searched(sandbox):
    result = search_code(sandbox, "CANARY", glob="*")

    assert result.ok
    assert result.meta["matches"] == 0
    assert sandbox.canary not in result.content


def test_results_are_capped(sandbox):
    result = search_code(sandbox, ".", glob="*.py", max_results=10_000)

    assert result.ok
    assert result.meta["matches"] <= MAX_MATCHES


def test_a_glob_that_matches_nothing_is_an_empty_success(sandbox):
    result = search_code(sandbox, "anything", glob="*.rs")

    assert result.ok
    assert result.meta["matches"] == 0
    assert result.meta["files_scanned"] == 0
