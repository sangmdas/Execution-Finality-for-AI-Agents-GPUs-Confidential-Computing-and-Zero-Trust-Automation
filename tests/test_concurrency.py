from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import pytest

from finality_ref.errors import ReplayDetected
from finality_ref.state import InMemoryConsumptionStore, SQLiteConsumptionStore
from .conftest import make_stack


def _race(sink, c, cap, contenders):
    def run(_):
        try:
            sink.effectuate(c, cap)
            return "ok"
        except ReplayDetected:
            return "replay"
        except Exception as exc:
            return type(exc).__name__
    with ThreadPoolExecutor(max_workers=contenders) as pool:
        return list(pool.map(run, range(contenders)))


@pytest.mark.parametrize("contenders", [2, 3, 4, 8, 16, 32, 64])
def test_inmemory_replay_race_exactly_one_effect(contenders):
    c, _, _, _, authority, eff, sink = make_stack(consumption=InMemoryConsumptionStore())
    cap = authority.authorize(c)
    results = _race(sink, c, cap, contenders)
    assert results.count("ok") == 1
    assert len(eff.records) == 1


@pytest.mark.parametrize("contenders", [2, 4, 8, 16, 32])
def test_sqlite_replay_race_exactly_one_effect(tmp_path, contenders):
    store = SQLiteConsumptionStore(tmp_path / f"consumed-{contenders}.db")
    c, _, _, _, authority, eff, sink = make_stack(consumption=store)
    cap = authority.authorize(c)
    results = _race(sink, c, cap, contenders)
    assert results.count("ok") == 1
    assert len(eff.records) == 1
    assert store.is_claimed(cap.capability_id)


@pytest.mark.parametrize("attempts", [2, 3, 5, 10, 25])
def test_sequential_replay_never_duplicates_effect(attempts):
    c, _, _, _, authority, eff, sink = make_stack()
    cap = authority.authorize(c)
    sink.effectuate(c, cap)
    for _ in range(attempts - 1):
        with pytest.raises(ReplayDetected):
            sink.effectuate(c, cap)
    assert len(eff.records) == 1
