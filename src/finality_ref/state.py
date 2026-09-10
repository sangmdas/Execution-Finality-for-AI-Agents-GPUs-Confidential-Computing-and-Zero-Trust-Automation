from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import sha256_hex
from .errors import ReplayDetected, ValidationDenied
from .models import CandidateAct, StateTransition


@dataclass
class SourceState:
    version: int
    quota: int
    budget: int


class ProtectedState:
    """Reference protected authority state.

    In production this state belongs in a rollback-resistant protected or trusted
    store. The implementation makes the state transition explicit and verifiable.
    """

    def __init__(self, *, default_quota: int = 1_000, default_budget: int = 1_000):
        self.default_quota = default_quota
        self.default_budget = default_budget
        self._sources: dict[str, SourceState] = {}
        self._nonces: dict[str, str] = {}
        self._transitions: dict[str, StateTransition] = {}
        self._lock = threading.RLock()

    @property
    def lock(self) -> threading.RLock:
        return self._lock

    def configure_source(self, source: str, *, quota: int, budget: int) -> None:
        with self._lock:
            self._sources[source] = SourceState(version=0, quota=quota, budget=budget)

    def _get_source(self, source: str) -> SourceState:
        return self._sources.setdefault(
            source,
            SourceState(version=0, quota=self.default_quota, budget=self.default_budget),
        )

    def transition_for_authorization(self, candidate: CandidateAct, *, cost: int = 1) -> StateTransition:
        if cost <= 0:
            raise ValueError("cost must be positive")
        with self._lock:
            if candidate.nonce in self._nonces:
                raise ReplayDetected("nonce already reserved or consumed")
            state = self._get_source(candidate.source)
            if state.quota < 1:
                raise ValidationDenied("quota_exhausted")
            if state.budget < cost:
                raise ValidationDenied("budget_exhausted")
            before_v, before_q, before_b = state.version, state.quota, state.budget
            after_v, after_q, after_b = before_v + 1, before_q - 1, before_b - cost
            transition_core: dict[str, Any] = {
                "nonce": candidate.nonce,
                "source": candidate.source,
                "before_version": before_v,
                "after_version": after_v,
                "quota_before": before_q,
                "quota_after": after_q,
                "budget_before": before_b,
                "budget_after": after_b,
                "policy_epoch": candidate.policy_epoch,
                "candidate_digest": candidate.digest(),
            }
            transition_id = sha256_hex(transition_core)
            transition = StateTransition(
                transition_id=transition_id,
                nonce=candidate.nonce,
                source=candidate.source,
                before_version=before_v,
                after_version=after_v,
                quota_before=before_q,
                quota_after=after_q,
                budget_before=before_b,
                budget_after=after_b,
                policy_epoch=candidate.policy_epoch,
            )
            state.version, state.quota, state.budget = after_v, after_q, after_b
            self._nonces[candidate.nonce] = transition_id
            self._transitions[transition_id] = transition
            return transition

    def verify_transition(self, transition_id: str, candidate: CandidateAct) -> bool:
        with self._lock:
            t = self._transitions.get(transition_id)
            return bool(
                t
                and t.nonce == candidate.nonce
                and t.source == candidate.source
                and t.policy_epoch == candidate.policy_epoch
                and t.after_version == t.before_version + 1
                and t.quota_after == t.quota_before - 1
                and t.budget_after < t.budget_before
                and self._nonces.get(candidate.nonce) == transition_id
            )

    def snapshot(self, source: str) -> SourceState:
        with self._lock:
            s = self._get_source(source)
            return SourceState(version=s.version, quota=s.quota, budget=s.budget)

    def get_transition(self, transition_id: str) -> StateTransition | None:
        with self._lock:
            return self._transitions.get(transition_id)


class InMemoryConsumptionStore:
    def __init__(self):
        self._claims: dict[str, tuple[str, str, str, int]] = {}
        self._lock = threading.Lock()

    def claim(self, capability_id: str, *, sink_id: str, boundary_id: str, nonce: str, now_ns: int) -> None:
        with self._lock:
            if capability_id in self._claims:
                raise ReplayDetected("capability already consumed")
            self._claims[capability_id] = (sink_id, boundary_id, nonce, now_ns)

    def is_claimed(self, capability_id: str) -> bool:
        with self._lock:
            return capability_id in self._claims


class SQLiteConsumptionStore:
    """Durable single-use claim store using a UNIQUE primary key.

    Each claim is a separate transaction. WAL plus a unique capability id provides
    a concrete replay race primitive suitable for the concurrency tests.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS consumed ("
                "capability_id TEXT PRIMARY KEY, sink_id TEXT NOT NULL, "
                "boundary_id TEXT NOT NULL, nonce TEXT NOT NULL, claimed_at_ns INTEGER NOT NULL)"
            )
        finally:
            conn.close()

    def claim(self, capability_id: str, *, sink_id: str, boundary_id: str, nonce: str, now_ns: int) -> None:
        conn = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT INTO consumed(capability_id,sink_id,boundary_id,nonce,claimed_at_ns) VALUES(?,?,?,?,?)",
                    (capability_id, sink_id, boundary_id, nonce, now_ns),
                )
            except sqlite3.IntegrityError as exc:
                conn.execute("ROLLBACK")
                raise ReplayDetected("capability already consumed") from exc
            else:
                conn.execute("COMMIT")
        finally:
            conn.close()

    def is_claimed(self, capability_id: str) -> bool:
        conn = sqlite3.connect(self.path)
        try:
            return conn.execute(
                "SELECT 1 FROM consumed WHERE capability_id=?", (capability_id,)
            ).fetchone() is not None
        finally:
            conn.close()
