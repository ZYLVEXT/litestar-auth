"""Failure-isolation tests for the framework-neutral observer seam."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import anyio
import pytest
from authweave_core import (
    SecurityOperation,
    SecurityOutcome,
    TraceCorrelation,
    ambient_trace_correlation,
    current_trace_correlation,
    observe_security,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

pytestmark = pytest.mark.unit


class _ObserverError(RuntimeError):
    pass


@dataclass
class _Observation:
    outcomes: list[tuple[SecurityOutcome, str | None]] = field(default_factory=list)
    fail_outcome: bool = False

    def set_outcome(self, outcome: SecurityOutcome, *, reason_code: str | None = None) -> None:
        if self.fail_outcome:
            raise _ObserverError
        self.outcomes.append((outcome, reason_code))


class _Observer:
    def __init__(self, *, failure: str | None = None) -> None:
        self.failure = failure
        self.observation = _Observation(fail_outcome=failure == "outcome")
        self.operations: list[tuple[SecurityOperation, tuple[TraceCorrelation, ...]]] = []

    @contextmanager
    def observe(
        self,
        operation: SecurityOperation,
        *,
        profile: str | None = None,
        principal_kind: str | None = None,
        credential_kind: str | None = None,
        links: Sequence[TraceCorrelation] = (),
    ) -> Iterator[_Observation]:
        _ = profile, principal_kind, credential_kind
        if self.failure == "enter":
            raise _ObserverError
        self.operations.append((operation, tuple(links)))
        try:
            yield self.observation
        finally:
            if self.failure == "exit":
                raise _ObserverError

    def current_correlation(self) -> TraceCorrelation | None:
        if self.failure == "correlation":
            raise _ObserverError
        return TraceCorrelation("1" * 32, "2" * 16)


def test_observation_records_bounded_outcome_and_links() -> None:
    observer = _Observer()
    link = TraceCorrelation("a" * 32, "b" * 16)

    with observe_security(observer, SecurityOperation.VERIFY_DPOP, links=(link,)) as observation:
        assert ambient_trace_correlation() == TraceCorrelation("1" * 32, "2" * 16)
        observation.set_outcome(SecurityOutcome.INVALID, reason_code="expired")

    assert observer.operations == [(SecurityOperation.VERIFY_DPOP, (link,))]
    assert observer.observation.outcomes == [(SecurityOutcome.INVALID, "expired")]
    assert current_trace_correlation(observer) == TraceCorrelation("1" * 32, "2" * 16)
    assert ambient_trace_correlation() is None
    assert current_trace_correlation(None) is None


@pytest.mark.parametrize("failure", ["enter", "outcome", "exit"])
def test_observer_failure_does_not_change_body_result(failure: str) -> None:
    observer = _Observer(failure=failure)

    with observe_security(observer, SecurityOperation.AUTHENTICATE) as observation:
        observation.set_outcome(SecurityOutcome.AUTHENTICATED)
        result = "authenticated"

    assert result == "authenticated"


def test_correlation_failure_returns_none() -> None:
    assert current_trace_correlation(_Observer(failure="correlation")) is None


def test_body_exception_has_precedence_over_observer_exit_failure() -> None:
    message = "body failure"
    with (
        pytest.raises(ValueError, match=message),
        observe_security(_Observer(failure="exit"), SecurityOperation.AUTHENTICATE),
    ):
        raise ValueError(message)


async def test_observer_context_preserves_async_context_and_cancellation() -> None:
    observer = _Observer()
    reached_after_await = False

    with anyio.move_on_after(0.01) as cancel_scope:
        with observe_security(observer, SecurityOperation.AUTHENTICATE) as observation:
            await anyio.sleep(1)
            reached_after_await = True
            observation.set_outcome(SecurityOutcome.AUTHENTICATED)

    assert cancel_scope.cancel_called
    assert not reached_after_await
    assert observer.operations == [(SecurityOperation.AUTHENTICATE, ())]


@pytest.mark.parametrize(
    ("trace_id", "span_id"),
    [("0" * 32, "1" * 16), ("1" * 32, "0" * 16), ("A" * 32, "1" * 16), ("1", "2")],
)
def test_trace_correlation_rejects_invalid_identifiers(trace_id: str, span_id: str) -> None:
    with pytest.raises(ValueError, match="must be"):
        TraceCorrelation(trace_id, span_id)
