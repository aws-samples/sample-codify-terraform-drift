"""The observation ledger: what makes "consecutive" a decidable claim.

The debounce exists so a flap cannot be codified. That only works if the count is honest,
so the tests here are mostly about the ways a count could be inflated: a retried build, a
run arriving out of order, a gap in the schedule, or a drifted value that changed since the
last sighting and should not inherit its predecessor's confirmation.
"""

from __future__ import annotations

import pytest

from driftcode.ledger import (
    CONSECUTIVE,
    DEFAULT_REQUIRED_SAMPLES,
    FIRST_OBSERVATION,
    GAP_RESET,
    OUT_OF_ORDER_IGNORED,
    RETRY_HELD,
    Ledger,
    LedgerError,
    MemoryStore,
    Observation,
    advance,
    build_store,
)

H1 = "a" * 64
H2 = "b" * 64
ADDRESS = "module.compute.aws_launch_template.app"


def ledger(required=DEFAULT_REQUIRED_SAMPLES) -> Ledger:
    return Ledger(MemoryStore(), required_samples=required)


# --- counting up -------------------------------------------------------------------


def test_a_first_sighting_counts_as_one():
    record, code, _ = advance(None, H1, ADDRESS, build_number=7, now=1000)

    assert record.consecutive_samples == 1
    assert record.first_seen_build == 7
    assert record.last_seen_build == 7
    assert code == FIRST_OBSERVATION


def test_the_next_build_increments():
    first, _, _ = advance(None, H1, ADDRESS, 7, now=1000)
    second, code, _ = advance(first, H1, ADDRESS, 8, now=2000)

    assert second.consecutive_samples == 2
    assert second.first_seen_build == 7
    assert second.last_seen_build == 8
    assert second.first_seen_at == 1000
    assert second.last_seen_at == 2000
    assert code == CONSECUTIVE


def test_two_consecutive_runs_confirm_the_drift():
    book = ledger()

    first = book.observe({ADDRESS: H1}, build_number=1)
    assert first[ADDRESS]["confirmed"] is False

    second = book.observe({ADDRESS: H1}, build_number=2)
    assert second[ADDRESS]["confirmed"] is True
    assert second[ADDRESS]["consecutive_samples"] == 2


def test_confirmation_persists_across_further_runs():
    book = ledger()
    for build in (1, 2, 3, 4):
        result = book.observe({ADDRESS: H1}, build_number=build)

    assert result[ADDRESS]["consecutive_samples"] == 4
    assert result[ADDRESS]["confirmed"] is True


# --- refusing to inflate the count -------------------------------------------------


def test_a_retried_build_does_not_advance_the_count():
    """Three retries of one run must not manufacture confirmation two runs establish."""
    book = ledger()

    book.observe({ADDRESS: H1}, build_number=1)
    again = book.observe({ADDRESS: H1}, build_number=1)
    third = book.observe({ADDRESS: H1}, build_number=1)

    assert again[ADDRESS]["consecutive_samples"] == 1
    assert third[ADDRESS]["consecutive_samples"] == 1
    assert again[ADDRESS]["confirmed"] is False
    assert again[ADDRESS]["code"] == RETRY_HELD


def test_a_gap_in_the_schedule_resets_the_count():
    """A missed run is exactly when the drift could have reverted and returned unseen."""
    book = ledger()

    book.observe({ADDRESS: H1}, build_number=1)
    book.observe({ADDRESS: H1}, build_number=2)
    after_gap = book.observe({ADDRESS: H1}, build_number=5)

    assert after_gap[ADDRESS]["consecutive_samples"] == 1
    assert after_gap[ADDRESS]["confirmed"] is False
    assert after_gap[ADDRESS]["code"] == GAP_RESET


def test_an_out_of_order_build_is_ignored_rather_than_rewriting_history():
    book = ledger()

    book.observe({ADDRESS: H1}, build_number=5)
    book.observe({ADDRESS: H1}, build_number=6)
    stale = book.observe({ADDRESS: H1}, build_number=4)

    assert stale[ADDRESS]["consecutive_samples"] == 2
    assert stale[ADDRESS]["last_seen_build"] == 6
    assert stale[ADDRESS]["code"] == OUT_OF_ORDER_IGNORED


def test_a_changed_value_starts_over_instead_of_inheriting_confirmation():
    """Keyed on the signature, so a new value cannot use the old value's history."""
    book = ledger()

    book.observe({ADDRESS: H1}, build_number=1)
    book.observe({ADDRESS: H1}, build_number=2)
    changed = book.observe({ADDRESS: H2}, build_number=3)

    assert changed[ADDRESS]["consecutive_samples"] == 1
    assert changed[ADDRESS]["confirmed"] is False


def test_resolved_drift_reappearing_after_a_gap_is_unconfirmed():
    book = ledger()
    book.observe({ADDRESS: H1}, build_number=1)
    book.observe({ADDRESS: H1}, build_number=2)

    # Drift is fixed; builds 3 and 4 see nothing. It comes back at build 5.
    returned = book.observe({ADDRESS: H1}, build_number=5)

    assert returned[ADDRESS]["consecutive_samples"] == 1


# --- multiple resources -------------------------------------------------------------


def test_signatures_are_counted_independently():
    book = ledger()
    other = "module.storage.aws_s3_bucket.data"

    book.observe({ADDRESS: H1}, build_number=1)
    result = book.observe({ADDRESS: H1, other: H2}, build_number=2)

    assert result[ADDRESS]["consecutive_samples"] == 2
    assert result[ADDRESS]["confirmed"] is True
    assert result[other]["consecutive_samples"] == 1
    assert result[other]["confirmed"] is False


def test_counts_returns_the_shape_the_scope_guard_consumes():
    book = ledger()
    book.observe({ADDRESS: H1}, build_number=1)
    observations = book.observe({ADDRESS: H1}, build_number=2)

    assert book.counts(observations) == {ADDRESS: 2}


def test_a_quiet_run_records_nothing():
    book = ledger()

    assert book.observe({}, build_number=1) == {}


# --- storage ------------------------------------------------------------------------


def test_records_round_trip_through_the_store():
    store = MemoryStore()
    record = Observation(H1, ADDRESS, 2, 7, 8, 1000, 2000)
    store.put(record, expected_last_seen_build=None)

    assert store.get(H1) == record


def test_a_record_carries_an_expiry_so_resolved_drift_ages_out():
    record = Observation(H1, ADDRESS, 1, 1, 1, last_seen_at=1000, first_seen_at=1000)

    assert record.as_item(retention_seconds=60)["expires_at"] == 1060


def test_a_concurrent_write_is_refused_rather_than_lost():
    """A lost write under-counts, which looks exactly like the debounce working."""
    store = MemoryStore()
    store.put(Observation(H1, ADDRESS, 1, 1, 1, 1000, 1000), expected_last_seen_build=None)

    with pytest.raises(LedgerError, match="concurrent modification"):
        store.put(Observation(H1, ADDRESS, 2, 1, 2, 1000, 2000), expected_last_seen_build=99)


def test_a_ledger_failure_propagates_rather_than_being_swallowed():
    class Broken(MemoryStore):
        def put(self, record, expected_last_seen_build):
            raise LedgerError("table unavailable")

    with pytest.raises(LedgerError):
        Ledger(Broken()).observe({ADDRESS: H1}, build_number=1)


def test_no_table_gives_an_in_memory_store_that_confirms_nothing():
    """The correct behaviour with no ledger configured: suppress, never invent."""
    store = build_store(None)
    book = Ledger(store)

    assert isinstance(store, MemoryStore)
    # A fresh process each run means every sighting is the first.
    assert book.observe({ADDRESS: H1}, build_number=1)[ADDRESS]["confirmed"] is False
    assert Ledger(build_store(None)).observe({ADDRESS: H1}, build_number=2)[ADDRESS][
        "consecutive_samples"
    ] == 1


def test_a_higher_requirement_delays_confirmation():
    book = ledger(required=3)

    book.observe({ADDRESS: H1}, build_number=1)
    assert book.observe({ADDRESS: H1}, build_number=2)[ADDRESS]["confirmed"] is False
    assert book.observe({ADDRESS: H1}, build_number=3)[ADDRESS]["confirmed"] is True
