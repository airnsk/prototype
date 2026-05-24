"""
Анализ экспериментальных данных.

Вычисление метрик:
- T_setup: время установления соединения
- T_revoke: время отзыва доступа
- K_avg: среднее число активных сессий
- AS̅: поверхность атаки (расчётная)
"""

import json
import statistics
from typing import List, Dict, Any, Optional


def calc_t_setup(events: List[Dict[str, Any]], ticket_id: str) -> Optional[float]:
    """T_setup = t_first_data - t_request для конкретного ticket_id."""
    req = None
    fd = None
    for e in events:
        if e.get("ticket_id") == ticket_id or (not e.get("ticket_id") and e.get("event") == "request"):
            if e["event"] == "request":
                req = e["ts"]
            elif e["event"] == "first_data":
                fd = e["ts"]
    if req and fd:
        return round((fd - req) * 1000, 2)  # ms
    return None


def calc_t_revoke(events: List[Dict[str, Any]], ticket_id: str) -> Optional[float]:
    """T_revoke = t_traffic_stop - t_revoke_cmd."""
    rc = None
    ts = None
    for e in events:
        if e.get("ticket_id") == ticket_id:
            if e["event"] == "revoke_cmd":
                rc = e["ts"]
            elif e["event"] == "traffic_stop":
                ts = e["ts"]
    if rc and ts:
        return round((ts - rc) * 1000, 2)
    return None


def calc_k_avg(events: List[Dict[str, Any]]) -> float:
    """Среднее число одновременно активных peer_add - traffic_stop."""
    # Упрощённая оценка: число peer_add минус число traffic_stop
    peer_adds = sum(1 for e in events if e["event"] == "peer_add")
    stops = sum(1 for e in events if e["event"] == "traffic_stop")
    return max(0, peer_adds - stops)


def calc_attack_surface(k_avg: int, num_users: int, num_services: int) -> Dict[str, int]:
    """Расчётная поверхность атаки для трёх архитектур."""
    return {
        "AS_vpn": num_users * num_services,
        "AS_ztna": num_users + num_services,
        "AS_direct": k_avg,
    }


def generate_report(events: List[Dict[str, Any]], num_users: int = 1, num_services: int = 1) -> Dict[str, Any]:
    """Сформировать сводный отчёт по эксперименту."""
    setups = []
    revokes = []
    
    # Собираем все ticket_id
    ticket_ids = set()
    for e in events:
        if e.get("ticket_id"):
            ticket_ids.add(e["ticket_id"])
    
    for tid in ticket_ids:
        t_s = calc_t_setup(events, tid)
        t_r = calc_t_revoke(events, tid)
        if t_s is not None:
            setups.append(t_s)
        if t_r is not None:
            revokes.append(t_r)
    
    k_avg = calc_k_avg(events)
    as_vals = calc_attack_surface(k_avg, num_users, num_services)
    
    report = {
        "num_events": len(events),
        "num_sessions": len(ticket_ids),
        "K_avg": k_avg,
        "attack_surface": as_vals,
    }
    
    if setups:
        report["T_setup_ms"] = {
            "avg": round(statistics.mean(setups), 2),
            "min": round(min(setups), 2),
            "max": round(max(setups), 2),
            "p95": round(statistics.quantiles(setups, n=20)[18], 2) if len(setups) >= 20 else None,
        }
    
    if revokes:
        report["T_revoke_ms"] = {
            "avg": round(statistics.mean(revokes), 2),
            "min": round(min(revokes), 2),
            "max": round(max(revokes), 2),
            "p95": round(statistics.quantiles(revokes, n=20)[18], 2) if len(revokes) >= 20 else None,
        }
    
    return report


def save_report(report: Dict[str, Any], path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
