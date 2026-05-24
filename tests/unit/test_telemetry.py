"""
Unit-тесты телеметрии.
"""

import pytest

from common.telemetry import TelemetryCollector, emit, get_collector


def test_emit_and_retrieve():
    col = TelemetryCollector()
    evt = col.emit("test-node", "test-event", ticket_id="jti-123")

    assert evt.node == "test-node"
    assert evt.event == "test-event"
    assert evt.ticket_id == "jti-123"
    assert evt.ts > 0

    all_events = col.all_events()
    assert len(all_events) == 1
    assert all_events[0].event == "test-event"


def test_filter():
    col = TelemetryCollector()
    col.emit("node-a", "request", ticket_id="t1")
    col.emit("node-b", "ticket_issued", ticket_id="t1")
    col.emit("node-a", "request", ticket_id="t2")

    assert len(col.filter(node="node-a")) == 2
    assert len(col.filter(event="ticket_issued")) == 1
    assert len(col.filter(ticket_id="t1")) == 2
    assert len(col.filter(node="node-a", event="request")) == 2


def test_clear():
    col = TelemetryCollector()
    col.emit("n", "e")
    assert len(col.all_events()) == 1
    col.clear()
    assert len(col.all_events()) == 0


def test_global_collector():
    col = get_collector()
    col.clear()
    evt = emit(node="global", event="test")
    assert evt.node == "global"
    assert len(col.all_events()) == 1
