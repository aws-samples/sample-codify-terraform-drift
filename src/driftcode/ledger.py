"""Count consecutive observations of the same drift, so the debounce means something.

The scope guard refuses to codify drift seen only once: a value that appears and reverts is
a flap, and codifying a flap writes it into the repository permanently. That check needs a
number no single run can produce, because "consecutive" is a statement about history. This
is where the history lives.

The record is keyed on the drift signature H, not on the resource address. That is what
makes the count mean what it says: if the drifted *value* changes between runs, H changes
too, and the new value starts at one observation instead of inheriting confirmation earned
by a different value.

Contiguity is decided by **build number, not elapsed time**. A time window has to guess the
cadence, and it silently accepts a gap if the schedule slips or a run fails. A build number
is monotonic per project, so the rule is exact: the previous observation must be the
immediately preceding build. Anything else - a skipped build, a failed build, a run out of
order - resets the count to one, because a missed run is precisely the case where the drift
could have reverted and returned unseen.

Re-observing within the same build is idempotent. A retried build must not advance the
count on its own, or three retries of one run would confirm drift that has been seen once.

Storage is behind a small interface with two implementations: an in-memory one used by
tests and local runs, and a DynamoDB one for the pipeline. The DynamoDB adapter imports
boto3 lazily so the rest of the package keeps its no-runtime-dependency property, and it
writes under an optimistic-concurrency condition rather than assuming it is the only writer.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import Any, Protocol

#: Records for drift nobody has seen in this long are expired by the store. Resolved drift
#: should disappear rather than accumulate, and a signature not seen for a month is either
#: resolved or so intermittent that its count should restart anyway.
DEFAULT_RETENTION_SECONDS = 30 * 24 * 3600

#: What the scope guard requires. Two consecutive observations, so a single flap cannot be
#: codified but a genuine change is not delayed longer than one cadence.
DEFAULT_REQUIRED_SAMPLES = 2

# Stable machine-readable outcomes, so callers and tests assert on the cause rather than on
# the sentence that explains it.
FIRST_OBSERVATION = "first_observation"
CONSECUTIVE = "consecutive"
RETRY_HELD = "retry_held"
OUT_OF_ORDER_IGNORED = "out_of_order_ignored"
GAP_RESET = "gap_reset"


class LedgerError(Exception):
    """Raised when an observation cannot be recorded, which must fail the run.

    Failing closed matters here: if the count cannot be written, the next run cannot
    establish consecutiveness, and silently proceeding would let an unconfirmed drift
    accumulate confirmation it never earned.
    """


@dataclass(frozen=True)
class Observation:
    """One signature's history."""

    signature: str
    address: str
    consecutive_samples: int
    first_seen_build: int
    last_seen_build: int
    first_seen_at: int
    last_seen_at: int

    def as_item(self, retention_seconds: int = DEFAULT_RETENTION_SECONDS) -> dict[str, Any]:
        return {
            "signature": self.signature,
            "address": self.address,
            "consecutive_samples": self.consecutive_samples,
            "first_seen_build": self.first_seen_build,
            "last_seen_build": self.last_seen_build,
            "first_seen_at": self.first_seen_at,
            "last_seen_at": self.last_seen_at,
            "expires_at": self.last_seen_at + retention_seconds,
        }

    @classmethod
    def from_item(cls, item: dict[str, Any]) -> "Observation":
        return cls(
            signature=str(item["signature"]),
            address=str(item.get("address", "")),
            consecutive_samples=int(item.get("consecutive_samples", 1)),
            first_seen_build=int(item.get("first_seen_build", 0)),
            last_seen_build=int(item.get("last_seen_build", 0)),
            first_seen_at=int(item.get("first_seen_at", 0)),
            last_seen_at=int(item.get("last_seen_at", 0)),
        )


def advance(
    previous: Observation | None,
    signature: str,
    address: str,
    build_number: int,
    now: int | None = None,
) -> tuple[Observation, str, str]:
    """Compute the next record for one signature, plus a stable code and prose.

    The code is the contract; the prose is carried into the output so an operator can see
    whether a count was incremented, held or reset without reconstructing it.
    """
    moment = int(now if now is not None else time.time())

    if previous is None:
        return (
            Observation(
                signature=signature,
                address=address,
                consecutive_samples=1,
                first_seen_build=build_number,
                last_seen_build=build_number,
                first_seen_at=moment,
                last_seen_at=moment,
            ),
            FIRST_OBSERVATION,
            "first observation of this signature",
        )

    if build_number == previous.last_seen_build:
        # A retried build. Advancing here would let three retries of one run manufacture
        # the confirmation that two separate runs are supposed to establish.
        return previous, RETRY_HELD, (
            f"already recorded for build {build_number}; a retry does not advance the count"
        )

    if build_number < previous.last_seen_build:
        # Out of order. Do not rewrite history backwards, and do not credit the run.
        return previous, OUT_OF_ORDER_IGNORED, (
            f"build {build_number} precedes the last recorded build "
            f"{previous.last_seen_build}; ignored rather than reordering history"
        )

    if build_number == previous.last_seen_build + 1:
        return (
            replace(
                previous,
                address=address,
                consecutive_samples=previous.consecutive_samples + 1,
                last_seen_build=build_number,
                last_seen_at=moment,
            ),
            CONSECUTIVE,
            f"consecutive with build {previous.last_seen_build}",
        )

    return (
        Observation(
            signature=signature,
            address=address,
            consecutive_samples=1,
            first_seen_build=build_number,
            last_seen_build=build_number,
            first_seen_at=moment,
            last_seen_at=moment,
        ),
        GAP_RESET,
        f"gap between builds {previous.last_seen_build} and {build_number}; the drift could "
        "have reverted and returned unseen, so the count restarts",
    )


class Store(Protocol):
    """The two operations a ledger needs. Kept minimal so adapters stay thin."""

    def get(self, signature: str) -> Observation | None: ...

    def put(self, record: Observation, expected_last_seen_build: int | None) -> None: ...


@dataclass
class MemoryStore:
    """In-process store for tests and local runs."""

    items: dict[str, dict[str, Any]] = field(default_factory=dict)

    def get(self, signature: str) -> Observation | None:
        item = self.items.get(signature)
        return Observation.from_item(item) if item else None

    def put(self, record: Observation, expected_last_seen_build: int | None) -> None:
        current = self.items.get(record.signature)
        actual = int(current["last_seen_build"]) if current else None
        if actual != expected_last_seen_build:
            raise LedgerError(
                f"concurrent modification of {record.signature}: expected last_seen_build "
                f"{expected_last_seen_build}, found {actual}"
            )
        self.items[record.signature] = record.as_item()


class DynamoStore:
    """DynamoDB-backed store, written under an optimistic-concurrency condition.

    boto3 is imported lazily so the package keeps its no-runtime-dependency property; only
    the pipeline, which installs the ``aws`` extra, ever constructs this.

    The conditional write is not decoration. Orchestration serializes runs per workspace, but
    that is a property of the caller, and a counter that silently loses a write would
    under-count and delay every codification behind it - a failure that looks like the
    debounce working.
    """

    def __init__(self, table_name: str, retention_seconds: int = DEFAULT_RETENTION_SECONDS):
        try:
            import boto3  # noqa: PLC0415 - deliberately lazy
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise LedgerError(
                "the DynamoDB ledger needs boto3; install the 'aws' extra "
                "(pip install '.[aws]')"
            ) from exc

        self._table = boto3.resource("dynamodb").Table(table_name)
        self._retention = retention_seconds

    def get(self, signature: str) -> Observation | None:
        try:
            response = self._table.get_item(Key={"signature": signature}, ConsistentRead=True)
        except Exception as exc:  # pragma: no cover - needs a live table
            raise LedgerError(f"could not read the observation ledger: {exc}") from exc
        item = response.get("Item")
        return Observation.from_item(item) if item else None

    def put(self, record: Observation, expected_last_seen_build: int | None) -> None:
        if expected_last_seen_build is None:
            condition = "attribute_not_exists(signature)"
            values: dict[str, Any] = {}
        else:
            condition = "last_seen_build = :expected"
            values = {":expected": expected_last_seen_build}

        try:
            self._table.put_item(
                Item=record.as_item(self._retention),
                ConditionExpression=condition,
                **({"ExpressionAttributeValues": values} if values else {}),
            )
        except Exception as exc:  # pragma: no cover - needs a live table
            raise LedgerError(
                f"could not record an observation for {record.signature}: {exc}. Failing "
                "closed, because a lost write under-counts and stalls every codification "
                "behind it"
            ) from exc


class Ledger:
    """Records observations and reports how many consecutive ones each signature has."""

    def __init__(self, store: Store, required_samples: int = DEFAULT_REQUIRED_SAMPLES):
        self.store = store
        self.required_samples = required_samples

    def observe(
        self,
        signatures: dict[str, str],
        build_number: int,
        now: int | None = None,
    ) -> dict[str, dict[str, Any]]:
        """Record this run's sighting of each signature and return the resulting counts.

        ``signatures`` maps resource address to signature. The result is keyed by address,
        which is what the scope guard works in.
        """
        out: dict[str, dict[str, Any]] = {}

        for address, signature in signatures.items():
            previous = self.store.get(signature)
            record, code, reason = advance(previous, signature, address, build_number, now)

            if previous is None or record != previous:
                self.store.put(
                    record,
                    expected_last_seen_build=previous.last_seen_build if previous else None,
                )

            out[address] = {
                "signature": signature,
                "consecutive_samples": record.consecutive_samples,
                "required_samples": self.required_samples,
                "confirmed": record.consecutive_samples >= self.required_samples,
                "first_seen_build": record.first_seen_build,
                "last_seen_build": record.last_seen_build,
                "code": code,
                "reason": reason,
            }

        return out

    def counts(self, observations: dict[str, dict[str, Any]]) -> dict[str, int]:
        """Address to consecutive-sample count, the shape the scope guard consumes."""
        return {address: o["consecutive_samples"] for address, o in observations.items()}


def build_store(table_name: str | None, retention_seconds: int = DEFAULT_RETENTION_SECONDS) -> Store:
    """A DynamoDB store when a table is named, an in-memory one otherwise.

    An in-memory store lasts one process, so every signature reads as a first observation
    and nothing is ever confirmed. That is the correct behaviour for a run with no ledger
    configured: it suppresses, rather than inventing confirmation.
    """
    if table_name:
        return DynamoStore(table_name, retention_seconds)
    return MemoryStore()
