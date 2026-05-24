"""
Сервер телеметрии для прототипа Direct-ZTNA.

Собирает события от всех узлов и предоставляет API для выгрузки.
"""

from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional, Dict, Any, List

from common.telemetry import TelemetryCollector, get_collector
from common.models import MetricEvent

app = FastAPI(title="Direct-ZTNA Telemetry")

_collector = get_collector()


class EventIn(BaseModel):
    node: str
    event: str
    ts: float
    ticket_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@app.post("/event")
async def post_event(evt: EventIn):
    _collector.emit(evt.node, evt.event, evt.ticket_id, evt.details)
    return {"status": "ok"}


@app.get("/events")
async def get_events():
    return {"events": [e.to_dict() for e in _collector.all_events()]}


@app.get("/report")
async def get_report():
    events = _collector.all_events()
    nodes = set(e.node for e in events)
    event_types = set(e.event for e in events)
    return {
        "total_events": len(events),
        "nodes": list(nodes),
        "event_types": list(event_types),
        "events": [e.to_dict() for e in events],
    }


@app.post("/clear")
async def clear_events():
    _collector.clear()
    return {"status": "cleared"}


@app.get("/health")
async def health():
    return {"status": "ok"}
