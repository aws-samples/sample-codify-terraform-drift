"""Turn a captured Terraform plan into a committable fixture.

Captured ``terraform show -json`` output is the only evidence in this repository that the
reconciliation, projection and classification logic works against a real provider rather
than against fixtures written by the same person who wrote the logic. Leaving it out means
the suite checks its own internal consistency, which is exactly the kind of confidence that
survives a wrong assumption.

There are two good reasons to leave it out, and this tool removes both:

  * **Size.** The full documents are ~230 KB combined, mostly ``configuration`` and
    provider metadata no test reads. Those sections are dropped.
  * **Identifiers.** Account IDs, IAM role unique IDs (``AROA…``), assumed-role session
    aliases, bucket names and AMI IDs are embedded throughout. Every one is replaced with a
    stable placeholder, so the shapes and the drift survive while the identifiers do not.

What is deliberately *not* changed: the structure, the attribute names, the actions, the
``null`` versus ``[]`` distinctions, and which resources appear in ``resource_drift`` versus
``resource_changes``. Those are the properties under test, and normalizing them would
recreate the problem this file exists to solve.

Run it from a workspace with captured plans present:

    python tests/redact_plan.py refresh-only.plan.json tests/fixtures/real-refresh-only.json

The result is verified by ``test_real_fixtures.py``, which fails if any identifier pattern
reappears - so a regression in this tool cannot quietly leak into a commit.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

#: Sections no test reads and which dominate the file size. `configuration` also carries
#: module source paths and provider versions that vary per capture without adding evidence.
DROPPED_TOP_LEVEL = ("configuration", "relevant_attributes")

#: Any AWS resource identifier: a lowercase prefix, a hyphen, then hex. Written as one generic
#: rule rather than an enumeration of prefixes, because an enumeration only covers the services
#: the capture happened to use - and the next capture uses a different one. The prefix and the
#: length survive so the shape is recognisable; the value does not.
RESOURCE_ID = re.compile(r"\b([a-z][a-z0-9]{1,12})-([0-9a-f]{8,})\b")

#: A bare hex run of 32 or more characters. Covers S3 canonical user IDs, which map to an AWS
#: account as directly as an account number does, plus ETags and content digests. Matched by
#: shape rather than by name because these appear under many different keys.
BARE_HEX = re.compile(r"\b[0-9a-f]{32,}\b")

#: Ordered: the account-ID rule must not fire before the ARN rule has consumed the ARN.
REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"arn:aws:[^\s\"]*"), "arn:aws:REDACTED"),
    (re.compile(r"AROA[A-Z0-9]{8,}"), "AROAREDACTEDROLEID"),
    (re.compile(r"AIDA[A-Z0-9]{8,}"), "AIDAREDACTEDUSERID"),
    (re.compile(r"\b\d{12}\b"), "000000000000"),
]

#: Values replaced wholesale rather than pattern-matched, because they are free text.
NAMED_REDACTIONS = {
    "owner_id": "000000000000",
    "caller_identity": "REDACTED",
    "user_id": "REDACTED",
    "session_name": "REDACTED",
}


def _zero_resource_id(match: re.Match[str]) -> str:
    prefix, value = match.group(1), match.group(2)
    return f"{prefix}-{'0' * len(value)}"


def _zero_bare_hex(match: re.Match[str]) -> str:
    return "0" * len(match.group(0))


def _redact_text(text: str) -> str:
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    # Shape-based rules run last, so a value already replaced by a named rule is left alone.
    text = RESOURCE_ID.sub(_zero_resource_id, text)
    text = BARE_HEX.sub(_zero_bare_hex, text)
    return text


def redact(value: Any, key: str | None = None) -> Any:
    """Recursively replace identifiers, preserving every structural distinction.

    ``None`` stays ``None`` and ``[]`` stays ``[]``: the difference between them is the
    provider-normalization signal the reconciler exists to suppress, so collapsing either
    would destroy the evidence.
    """
    if key in NAMED_REDACTIONS and isinstance(value, str):
        return NAMED_REDACTIONS[key]
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        return {k: redact(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, key) for v in value]
    return value


def reduce_plan(document: dict[str, Any]) -> dict[str, Any]:
    """Drop sections no test reads, then redact everything that remains."""
    trimmed = {k: v for k, v in document.items() if k not in DROPPED_TOP_LEVEL}
    return redact(trimmed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", help="captured terraform show -json output")
    parser.add_argument("destination", help="where to write the committable fixture")
    args = parser.parse_args(argv)

    with open(args.source, encoding="utf-8") as fh:
        document = json.load(fh)

    reduced = reduce_plan(document)

    with open(args.destination, "w", encoding="utf-8") as fh:
        json.dump(reduced, fh, indent=1, sort_keys=True)

    original = len(json.dumps(document))
    final = len(json.dumps(reduced))
    print(
        f"{args.source} -> {args.destination}: {original:,} -> {final:,} bytes",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
