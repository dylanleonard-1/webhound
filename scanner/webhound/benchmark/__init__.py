# WebHound — webhound/benchmark/__init__.py
# Phase-5E scanner quality validation harness.
#
# A benchmark site is a (named, declarative) fixture describing what
# the scanner is expected to find and NOT find. The harness runs the
# scanner against the fixture, compares against the expectations,
# and produces a BenchmarkResult with precision/recall and per-
# expectation pass/fail. Used by CI to catch regressions in
# false-positive and false-negative rate as the scanner evolves.
