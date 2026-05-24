"""Shared validation primitives for plugin configuration checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from litestar_auth.exceptions import ConfigurationError

if TYPE_CHECKING:
    from collections.abc import Iterable


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    """A single plugin configuration validation issue."""

    message: str
    field: str | None = None


def format_validation_issues(issues: Iterable[ValidationIssue]) -> str:
    """Format validation issues for ``ConfigurationError``.

    Returns:
        A stable user-facing validation message.
    """
    issue_list = tuple(issues)
    if not issue_list:
        return "Invalid LitestarAuth configuration."
    if len(issue_list) == 1:
        return issue_list[0].message
    messages = "\n".join(f"- {issue.message}" for issue in issue_list)
    return f"Invalid LitestarAuth configuration:\n{messages}"


class IssueCollector:
    """Collect plugin validation issues and raise one formatted configuration error."""

    __slots__ = ("_issues",)

    def __init__(self) -> None:
        self._issues: list[ValidationIssue] = []

    @property
    def issues(self) -> tuple[ValidationIssue, ...]:
        """Collected validation issues."""
        return tuple(self._issues)

    def add(self, message: str, *, field: str | None = None) -> None:
        """Add one validation issue."""
        self._issues.append(ValidationIssue(message=message, field=field))

    def extend(self, issues: Iterable[ValidationIssue]) -> None:
        """Add multiple validation issues."""
        self._issues.extend(issues)

    def raise_if_any(self) -> None:
        """Raise ``ConfigurationError`` when at least one issue was collected.

        Raises:
            ConfigurationError: If any validation issues were collected.
        """
        if self._issues:
            raise ConfigurationError(format_validation_issues(self._issues))


def raise_configuration_error(message: str, *, field: str | None = None) -> None:
    """Raise one consistently formatted plugin ``ConfigurationError``.

    Raises:
        ConfigurationError: Always.
    """
    raise ConfigurationError(format_configuration_message(message, field=field))


def format_configuration_message(message: str, *, field: str | None = None) -> str:
    """Format one validation issue with the shared plugin formatter.

    Returns:
        A stable user-facing validation message.
    """
    return format_validation_issues((ValidationIssue(message=message, field=field),))


def require_non_empty(
    collector: IssueCollector,
    value: object,
    *,
    field: str,
    message: str | None = None,
) -> None:
    """Collect an issue when ``value`` is empty or unset."""
    if not value:
        collector.add(message or f"{field} must be configured.", field=field)


def require_callable(
    collector: IssueCollector,
    value: object,
    *,
    field: str,
    message: str | None = None,
) -> None:
    """Collect an issue when ``value`` is not callable."""
    if not callable(value):
        collector.add(message or f"{field} must be callable.", field=field)


def require_secret_length(
    collector: IssueCollector,
    secret: str | bytes | None,
    *,
    field: str,
    minimum_length: int,
    message: str | None = None,
) -> None:
    """Collect an issue when secret material is missing or shorter than required."""
    if secret is None or len(secret) < minimum_length:
        collector.add(message or f"{field} must be at least {minimum_length} characters.", field=field)
