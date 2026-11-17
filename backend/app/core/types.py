"""Strict input types for request models (P7, found by API fuzzing).

Pydantic's lax mode accepts ``0``/``1`` for booleans, numeric strings for integers and bare
numbers as Unix timestamps. For
safety switches (kill switch, AI cloud egress, PII redaction) and time windows the API now
requires real JSON booleans and ISO-8601 date-times, so a malformed client cannot flip a
switch or move a window by accident.
"""

from datetime import datetime
from typing import Annotated, Any

from pydantic import BeforeValidator, Strict


def _iso_only(value: Any) -> Any:
    if isinstance(value, bool | int | float):
        raise ValueError("use an ISO-8601 date-time")
    if isinstance(value, str):
        try:
            float(value)  # numbers in any notation (1.5, -9e-259, inf, nan) are not date-times
        except ValueError:
            return value
        raise ValueError("use an ISO-8601 date-time")
    return value


StrictBool = Annotated[bool, Strict()]
StrictInt = Annotated[int, Strict()]
IsoDatetime = Annotated[datetime, BeforeValidator(_iso_only)]

# Upper bound for integer cursors compared with Postgres bigint columns (fuzzing found a 500).
PG_BIGINT_MAX = 2**63 - 1
