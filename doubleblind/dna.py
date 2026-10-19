"""Contamination DNA: per-session canary markers and leak attribution.

Every session is issued markers that are unique to it.  A context marker is
placed in that session's model context; a payload marker is attached to the
material the session submits.  The gateway scans everything it is about to
release and treats any marker belonging to a *different* session as evidence
that content has crossed a session boundary.  Because markers are keyed to the
session that owns them, a hit names the source, not just the fact of a leak.

What this detects: verbatim propagation of marked content.
What it does not detect: paraphrase, summarisation, or semantic influence that
carries no marker.  That limit is deliberate and is stated in the threat model
rather than hidden; a green detector is not a proof of non-contamination.
"""

from __future__ import annotations

import re
import secrets
import threading
from dataclasses import dataclass, field
from typing import Iterable

#: Markers are recognisable, fixed-width and unlikely to arise naturally.
MARKER_RE = re.compile(r"DBX-[A-Z]{3}-[0-9a-f]{8}-[0-9a-f]{16}")

CONTEXT = "CTX"
PAYLOAD = "PLD"


@dataclass(frozen=True)
class Marker:
    value: str
    session_id: str
    party: str
    kind: str


@dataclass
class LeakHit:
    """One foreign marker observed in a message that was about to be released."""

    marker: str
    source_session: str
    source_party: str
    kind: str
    observed_in_session: str
    observed_in_party: str

    def describe(self) -> str:
        return (
            "marker %s (%s of session %s, party %s) observed in session %s "
            "destined for %s"
            % (
                self.marker,
                self.kind,
                self.source_session,
                self.source_party,
                self.observed_in_session,
                self.observed_in_party,
            )
        )


class DnaRegistry:
    """Issues markers and attributes any marker it later sees."""

    def __init__(self) -> None:
        self._by_value: dict[str, Marker] = {}
        self._by_session: dict[str, list[Marker]] = {}
        self._lock = threading.Lock()

    def issue(self, session_id: str, party: str, kind: str) -> Marker:
        value = "DBX-%s-%s-%s" % (
            kind.upper()[:3],
            session_id[:8].ljust(8, "0"),
            secrets.token_hex(8),
        )
        marker = Marker(value=value, session_id=session_id, party=party, kind=kind)
        with self._lock:
            self._by_value[value] = marker
            self._by_session.setdefault(session_id, []).append(marker)
        return marker

    def markers_for(self, session_id: str) -> list[Marker]:
        with self._lock:
            return list(self._by_session.get(session_id, ()))

    def lookup(self, value: str) -> Marker | None:
        with self._lock:
            return self._by_value.get(value)

    def scan(
        self, text: str, *, session_id: str, party: str
    ) -> list[LeakHit]:
        """Return every marker in ``text`` that belongs to another session."""
        hits: list[LeakHit] = []
        for value in dict.fromkeys(MARKER_RE.findall(text)):
            owner = self.lookup(value)
            if owner is None:
                # A well-formed marker we never issued is itself suspicious:
                # either a forged marker or state surviving from an earlier run.
                hits.append(
                    LeakHit(
                        marker=value,
                        source_session="<unknown>",
                        source_party="<unknown>",
                        kind="unattributed",
                        observed_in_session=session_id,
                        observed_in_party=party,
                    )
                )
                continue
            if owner.session_id != session_id:
                hits.append(
                    LeakHit(
                        marker=value,
                        source_session=owner.session_id,
                        source_party=owner.party,
                        kind=owner.kind,
                        observed_in_session=session_id,
                        observed_in_party=party,
                    )
                )
        return hits

    @staticmethod
    def strip(text: str) -> str:
        """Remove every well-formed marker, for material leaving the system."""
        return MARKER_RE.sub("", text)


@dataclass
class SessionDna:
    """The marker set belonging to one session."""

    session_id: str
    party: str
    context: Marker
    payload: Marker
    extra: list[Marker] = field(default_factory=list)

    def all_values(self) -> Iterable[str]:
        yield self.context.value
        yield self.payload.value
        for m in self.extra:
            yield m.value


def provision(registry: DnaRegistry, session_id: str, party: str) -> SessionDna:
    """Issue the standard marker set for a new session."""
    return SessionDna(
        session_id=session_id,
        party=party,
        context=registry.issue(session_id, party, CONTEXT),
        payload=registry.issue(session_id, party, PAYLOAD),
    )
