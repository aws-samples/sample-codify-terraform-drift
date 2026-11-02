"""Positive allowlist for Terraform invocations in the detection stage.

Detection must never mutate infrastructure or persist state. A *denylist* on the
strings ``apply``/``refresh`` cannot achieve this: ``-refresh-only`` is a planning
*mode flag* available to both ``plan`` and ``apply``, so a substring match either

  * rejects the safe ``terraform plan -refresh-only`` (breaking detection), or
  * permits ``terraform apply -refresh-only`` — the one refresh variant that
    *writes a refreshed snapshot to the backend*.

So this guard parses argv, identifies the subcommand as the first non-flag token,
and permits only an explicit allowlist. Anything unrecognised is rejected, which
means a new mutating subcommand fails closed rather than slipping through.

This is a defence-in-depth layer. The authoritative read-only guarantee is the IAM
DENY on ``s3:PutObject``/``s3:DeleteObject`` for the state key — a guard in the
build script cannot bind a principal, but IAM can.

**The guard executes Terraform itself.** A guard that only validates an argument list
and prints a verdict, leaving the caller to type the real command on the next line, binds
nothing: the validated string and the executed string are separate text, so a copy-paste
slip, an edit to one line but not the other, or a reordering silently produces an
unguarded invocation that still logs a "permitted" line. Validating one command and
running another is not a guard, it is a comment. So the only way to run Terraform in this
pipeline is *through* here, and the argv that is checked is the argv that is executed.
"""

from __future__ import annotations

import os
import shutil
import sys

#: Subcommands the detection stage legitimately needs. All are read-only with
#: respect to managed infrastructure.
ALLOWED_SUBCOMMANDS = frozenset(
    {
        "init",       # required to configure the S3 backend before planning
        "plan",       # both the locked refresh-only plan and the full plan
        "show",       # rendering a saved plan as JSON
        "providers",  # `providers schema -json`, used by Gate A completeness checks
        "validate",
        "fmt",
        "version",
    }
)

#: Rejected with a specific message because the reason matters to an operator.
EXPLICIT_DENIALS = {
    "apply": "applies changes; `apply -refresh-only` also persists refreshed state",
    "destroy": "destroys infrastructure",
    "refresh": "deprecated alias that persists refreshed state",
    "import": "mutates state",
    "state": "state subcommands can rewrite state",
    "taint": "mutates state",
    "untaint": "mutates state",
    "force-unlock": "would defeat the locking guarantee detection depends on",
    "workspace": "can switch the state file out from under the run",
    "login": "not needed; handles credentials",
    "logout": "not needed; handles credentials",
}

#: Flags that make an otherwise-safe subcommand unsafe. This is where the substring-versus-
#: flag problem actually bites: every entry here is dangerous on a subcommand the allowlist
#: permits, so checking the subcommand alone is not enough.
#:
#: A key with `=` is matched exactly, so `-refresh=false` is rejected while `-refresh=true`
#: is not. A key without `=` is matched on the flag name, so `-target=x` and `-target x`
#: are both caught.
DENIED_FLAGS = {
    "-migrate-state": "would rewrite state during init",
    "-lock=false": "disables locking; detection requires a lock so it reads a consistent snapshot and fails loudly on contention",
    # `plan -destroy` is read-only in itself, but it produces a plan in which every managed
    # resource is a deletion. Reconciliation would read that as universal delete-class
    # drift, and the saved plan file is one `apply` away from destroying the estate.
    # Detection never needs a destroy plan.
    "-destroy": "produces a destroy plan; reconciliation would read every resource as delete-class drift, and the saved plan is one apply away from destroying the estate",
    # `-replace` fabricates a replacement for a resource that did not ask for one, which
    # defeats the ForceNew discrimination the two-plan reconciliation depends on.
    "-replace": "fabricates a replacement, which corrupts the replacement-class discrimination between the two plans",
    # A targeted plan silently narrows the observed surface, so Gate A would assert
    # completeness over a subset while claiming it covered the projection.
    "-target": "narrows the plan to a subset, so completeness cannot be asserted over the surface Gate A claims to have covered",
    # An unrefreshed plan does not reflect live state, so it cannot serve as the
    # discriminator that separates real drift from provider normalization.
    "-refresh=false": "skips refresh, so the plan no longer reflects live state and cannot discriminate real drift from normalization",
}


def _subcommand(args: list[str]) -> str | None:
    """First non-flag token, ignoring Terraform's global flags."""
    for tok in args:
        if tok.startswith("-"):
            continue
        return tok
    return None


def validate(args: list[str]) -> tuple[bool, str]:
    """Validate Terraform arguments (argv *after* the ``terraform`` binary).

    Returns ``(ok, reason)``. ``reason`` is empty when permitted.

    Flags are checked before the subcommand, because the dangerous cases are flags on
    permitted subcommands: ``plan -destroy`` is a destroy plan, ``plan -target=x`` is a
    partial one, and neither is caught by looking at the word ``plan``.
    """
    for tok in args:
        name = tok.split("=", 1)[0].lower()
        for flag, why in DENIED_FLAGS.items():
            if "=" in flag:
                # Value-sensitive: -refresh=false is refused, -refresh=true is fine.
                if tok.lower() == flag:
                    return False, f"flag `{flag}` is not permitted: {why}"
            elif name == flag:
                # Name-only: catches both `-target=x` and `-target x`.
                return False, f"flag `{flag}` is not permitted: {why}"

    sub = _subcommand(args)
    if sub is None:
        return False, "no subcommand supplied"
    if sub in EXPLICIT_DENIALS:
        return False, f"subcommand `{sub}` is not permitted: {EXPLICIT_DENIALS[sub]}"
    if sub not in ALLOWED_SUBCOMMANDS:
        return False, (
            f"subcommand `{sub}` is not on the allowlist "
            f"({', '.join(sorted(ALLOWED_SUBCOMMANDS))}); rejected fail-closed"
        )
    return True, ""


def main(argv: list[str] | None = None) -> int:
    """Validate the arguments, then replace this process with Terraform running them.

    ``--check-only`` validates without executing, for tests and for a dry run. It is not
    what the pipeline uses: a guard that only advises is one edit away from being bypassed.
    """
    args = list(argv if argv is not None else sys.argv[1:])

    check_only = "--check-only" in args
    if check_only:
        args = [a for a in args if a != "--check-only"]

    ok, reason = validate(args)
    if not ok:
        print(f"tf_guard: REJECTED `terraform {' '.join(args)}`\n  {reason}", file=sys.stderr)
        return 2

    if check_only:
        print(f"tf_guard: permitted `terraform {' '.join(args)}` (not executed)", file=sys.stderr)
        return 0

    binary = shutil.which("terraform")
    if binary is None:
        print("tf_guard: terraform is not on PATH", file=sys.stderr)
        return 127

    print(f"tf_guard: running `terraform {' '.join(args)}`", file=sys.stderr)
    sys.stderr.flush()
    sys.stdout.flush()

    # execv, not a subprocess: the checked argv becomes the running process, so there is
    # no window in which a different command could be substituted, and Terraform's exit
    # status and streams reach the build directly.
    os.execv(binary, [binary, *args])


if __name__ == "__main__":
    raise SystemExit(main())
