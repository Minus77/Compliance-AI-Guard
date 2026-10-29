from concurrent.futures import ThreadPoolExecutor

from compliance_guard.audit.trace import Tracer


def test_shared_tracer_records_concurrent_spans():
    tracer = Tracer()
    workers = 8
    spans_per_worker = 100

    def record(_: int) -> None:
        for _ in range(spans_per_worker):
            tracer.start("check", trace_id="trace-concurrent")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        list(pool.map(record, range(workers)))

    assert len(tracer.spans_for_trace("trace-concurrent")) == workers * spans_per_worker
