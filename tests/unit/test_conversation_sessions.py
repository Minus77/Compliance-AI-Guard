import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from compliance_guard.workflow.conversation_sessions import (
    ConversationExpiredError,
    ConversationStore,
    ConversationStaleError,
)


def _create(store: ConversationStore, suffix: str = "1"):
    return store.create(
        tenant_id="TENANT-A",
        actor_id="actor-1",
        inspected_content_sha256="hash",
        safe_content="safe",
        content_version="content-1",
        rule_version="rules-1",
        allowed_constraints={"suffix": suffix},
    )


def test_concurrent_consume_allows_exactly_one_generation():
    store = ConversationStore()
    session = _create(store)
    workers = 8
    start = threading.Barrier(workers)

    def consume():
        start.wait()
        try:
            return store.consume(
                session.conversation_id,
                "TENANT-A",
                "actor-1",
                "rules-1",
            )
        except (ConversationExpiredError, ConversationStaleError):
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(consume) for _ in range(workers)]
        results = [future.result(timeout=1) for future in futures]

    assert sum(result is not None for result in results) == 1
    with pytest.raises(ConversationExpiredError):
        store.get(session.conversation_id, "TENANT-A", "actor-1", "rules-1")


def test_returned_sessions_cannot_mutate_store_state():
    store = ConversationStore()
    session = _create(store)
    session.allowed_constraints["suffix"] = "changed"

    assert store.get(
        session.conversation_id, "TENANT-A", "actor-1", "rules-1"
    ).allowed_constraints == {"suffix": "1"}
