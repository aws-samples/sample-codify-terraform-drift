"""Guard tests. The central case is that `plan -refresh-only` is permitted while
`apply -refresh-only` is rejected — the distinction a substring denylist cannot make.
"""

from __future__ import annotations

import pytest

from driftcode.detect.tf_guard import main, validate


def ok(*args):
    permitted, reason = validate(list(args))
    assert permitted, f"expected permitted, got rejection: {reason}"


def rejected(*args):
    permitted, reason = validate(list(args))
    assert not permitted, "expected rejection, was permitted"
    return reason


# --- the distinction that matters ------------------------------------------

def test_locked_refresh_only_plan_is_permitted():
    ok("plan", "-refresh-only", "-out=drift.tfplan")


def test_apply_refresh_only_is_rejected():
    """The one refresh variant that persists state to the backend."""
    reason = rejected("apply", "-refresh-only", "-auto-approve")
    assert "persists refreshed state" in reason


def test_bare_apply_is_rejected():
    assert "applies changes" in rejected("apply", "-auto-approve")


def test_refresh_subcommand_is_rejected():
    assert "persists refreshed state" in rejected("refresh")


# --- what detection needs --------------------------------------------------

def test_detection_sequence_is_permitted():
    ok("init")
    ok("plan", "-out=full.tfplan")
    ok("show", "-json", "drift.tfplan")
    ok("providers", "schema", "-json")


def test_global_flags_before_subcommand_are_skipped():
    ok("-chdir=environments/dev", "plan", "-refresh-only")


def test_apply_still_rejected_behind_global_flags():
    rejected("-chdir=environments/dev", "apply")


# --- fail-closed behaviour -------------------------------------------------

def test_unknown_subcommand_fails_closed():
    assert "fail-closed" in rejected("some-new-mutating-command")


def test_no_subcommand_is_rejected():
    assert "no subcommand" in rejected("-json")


def test_state_and_force_unlock_are_rejected():
    assert "rewrite state" in rejected("state", "rm", "aws_vpc.main")
    assert "locking guarantee" in rejected("force-unlock", "abc123")


def test_destroy_and_import_are_rejected():
    rejected("destroy", "-auto-approve")
    rejected("import", "aws_vpc.main", "vpc-123")


# --- unsafe flags on otherwise-safe subcommands ----------------------------

def test_lock_false_is_rejected_even_on_plan():
    """Detection must hold a real lock: -lock=false admits torn reads and makes the
    missed-cadence alert unreachable."""
    assert "disables locking" in rejected("plan", "-refresh-only", "-lock=false")


def test_migrate_state_on_init_is_rejected():
    assert "rewrite state" in rejected("init", "-migrate-state")


def test_lock_timeout_is_permitted():
    ok("plan", "-refresh-only", "-lock-timeout=60s")



# --- the guard is a wrapper, not an adviser ----------------------------------------
#
# A guard that only validates an argument list and prints a verdict leaves the caller to
# type the real command on the next line. Nothing binds the two, so an edit to one line
# and not the other produces an unguarded invocation that still logs "permitted".


def test_a_rejected_command_is_never_executed(monkeypatch):
    executed = []
    monkeypatch.setattr("driftcode.detect.tf_guard.os.execv", lambda *a: executed.append(a))
    monkeypatch.setattr("driftcode.detect.tf_guard.shutil.which", lambda _: "/usr/bin/terraform")

    assert main(["apply", "-refresh-only"]) == 2
    assert executed == []


def test_a_permitted_command_replaces_the_process_with_the_argv_that_was_checked():
    """The checked argv must be the executed argv - not a copy the caller retypes."""
    calls = []

    import driftcode.detect.tf_guard as guard

    original_execv, original_which = guard.os.execv, guard.shutil.which
    guard.os.execv = lambda binary, argv: calls.append((binary, argv))
    guard.shutil.which = lambda _: "/usr/bin/terraform"
    try:
        main(["-chdir=/tmp/target", "plan", "-refresh-only", "-lock-timeout=120s"])
    finally:
        guard.os.execv, guard.shutil.which = original_execv, original_which

    assert calls == [
        (
            "/usr/bin/terraform",
            [
                "/usr/bin/terraform",
                "-chdir=/tmp/target",
                "plan",
                "-refresh-only",
                "-lock-timeout=120s",
            ],
        )
    ]


def test_the_global_chdir_flag_does_not_hide_the_subcommand():
    """-chdir precedes the subcommand, so the parser must still find `apply`."""
    ok, reason = validate(["-chdir=/tmp/target", "apply"])

    assert not ok
    assert "apply" in reason


def test_chdir_is_permitted_alongside_an_allowed_subcommand():
    ok, _ = validate(["-chdir=/tmp/target", "plan", "-refresh-only"])

    assert ok


def test_check_only_validates_without_executing(monkeypatch):
    executed = []
    monkeypatch.setattr("driftcode.detect.tf_guard.os.execv", lambda *a: executed.append(a))

    assert main(["--check-only", "plan", "-refresh-only"]) == 0
    assert executed == []


def test_check_only_still_rejects(monkeypatch):
    executed = []
    monkeypatch.setattr("driftcode.detect.tf_guard.os.execv", lambda *a: executed.append(a))

    assert main(["--check-only", "destroy"]) == 2
    assert executed == []


def test_a_missing_terraform_binary_fails_rather_than_silently_succeeding(monkeypatch):
    monkeypatch.setattr("driftcode.detect.tf_guard.shutil.which", lambda _: None)

    assert main(["plan"]) == 127



# --- dangerous FLAGS on permitted subcommands ---------------------------------------
#
# The guard's whole reason for existing is that danger does not live in the subcommand
# alone. `plan` is on the allowlist; `plan -destroy` is a destroy plan. Checking the word
# `plan` catches neither this nor a targeted plan that silently narrows the surface Gate A
# claims to have covered.


@pytest.mark.parametrize(
    "args",
    [
        ["plan", "-destroy"],
        ["plan", "-destroy", "-out=/tmp/p.tfplan"],
        ["-chdir=/tmp/target", "plan", "-destroy"],
        ["plan", "-refresh-only", "-destroy"],
        ["apply", "-destroy"],
    ],
)
def test_a_destroy_plan_is_rejected(args):
    """Read-only in itself, but it renders every resource as a deletion.

    Reconciliation would read that as universal delete-class drift, and the saved plan file
    is one apply away from destroying the estate. Detection never needs one.
    """
    ok, reason = validate(args)

    assert not ok
    assert "-destroy" in reason or "apply" in reason


@pytest.mark.parametrize(
    "args,expected",
    [
        (["plan", "-target=aws_instance.web"], "-target"),
        (["plan", "-target", "aws_instance.web"], "-target"),
        (["plan", "-replace=aws_instance.web"], "-replace"),
        (["plan", "-refresh=false"], "-refresh=false"),
        (["plan", "-refresh-only", "-lock=false"], "-lock=false"),
        (["init", "-migrate-state"], "-migrate-state"),
    ],
)
def test_flags_that_invalidate_the_run_are_rejected(args, expected):
    ok, reason = validate(args)

    assert not ok
    assert expected in reason


@pytest.mark.parametrize(
    "args",
    [
        ["plan", "-refresh-only"],
        ["plan", "-refresh=true"],
        ["plan", "-refresh-only", "-lock=true"],
        ["plan", "-refresh-only", "-lock-timeout=120s"],
        ["plan", "-out=/tmp/p.tfplan", "-input=false", "-no-color"],
        ["show", "-json", "/tmp/p.tfplan"],
        ["providers", "schema", "-json"],
        ["init", "-input=false", "-no-color"],
    ],
)
def test_the_flags_detection_actually_uses_are_permitted(args):
    """The denylist must not swallow the pipeline's own invocations."""
    ok, reason = validate(args)

    assert ok, reason


def test_refresh_true_is_permitted_while_refresh_false_is_not():
    """Value-sensitive matching: the flag name alone is not the problem."""
    assert validate(["plan", "-refresh=true"])[0]
    assert not validate(["plan", "-refresh=false"])[0]


def test_flag_matching_is_case_insensitive():
    assert not validate(["plan", "-LOCK=FALSE"])[0]
    assert not validate(["plan", "-Destroy"])[0]


def test_a_denied_flag_is_caught_before_the_subcommand_is_considered():
    """Otherwise a permitted subcommand would mask a dangerous flag."""
    ok, reason = validate(["-chdir=/tmp/x", "plan", "-refresh-only", "-destroy"])

    assert not ok
    assert "-destroy" in reason


def test_a_destroy_plan_is_never_executed(monkeypatch):
    executed = []
    monkeypatch.setattr("driftcode.detect.tf_guard.os.execv", lambda *a: executed.append(a))
    monkeypatch.setattr("driftcode.detect.tf_guard.shutil.which", lambda _: "/usr/bin/terraform")

    assert main(["plan", "-destroy"]) == 2
    assert executed == []
