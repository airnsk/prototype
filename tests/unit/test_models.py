"""
Unit-тесты моделей данных.
"""

from common.models import AccessTicket, TransportProfile, MetricEvent, RevokeCommand


def test_transport_profile_roundtrip():
    tp = TransportProfile(
        server_pubkey="pubkey123",
        endpoint="10.0.0.1:51820",
        allowed_ips=["10.0.0.1/32"],
    )
    d = tp.to_dict()
    tp2 = TransportProfile.from_dict(d)
    assert tp2.server_pubkey == tp.server_pubkey
    assert tp2.endpoint == tp.endpoint
    assert tp2.allowed_ips == tp.allowed_ips


def test_access_ticket_roundtrip():
    tp = TransportProfile(
        server_pubkey="pubkey123",
        endpoint="10.0.0.1:51820",
        allowed_ips=["10.0.0.1/32"],
    )
    ticket = AccessTicket(
        iss="controller",
        aud="client",
        sub="alice",
        service_id="s1",
        jti="jti-abc",
        nbf=1000,
        iat=1000,
        exp=2000,
        key_id="psk-alice-s1",
        transport=tp,
        scope="tcp:443",
        sig="deadbeef",
    )
    d = ticket.to_dict()
    ticket2 = AccessTicket.from_dict(d)

    assert ticket2.iss == ticket.iss
    assert ticket2.aud == ticket.aud
    assert ticket2.sub == ticket.sub
    assert ticket2.sig == ticket.sig
    assert ticket2.transport.server_pubkey == tp.server_pubkey

    # payload_dict не содержит sig
    payload = ticket.payload_dict()
    assert "sig" not in payload
    assert payload["jti"] == "jti-abc"


def test_revoke_command_roundtrip():
    rc = RevokeCommand(jti="jti-abc", revoked_at=1234, reason="test")
    d = rc.to_dict()
    rc2 = RevokeCommand.from_dict(d)
    assert rc2.jti == rc.jti
    assert rc2.revoked_at == rc.revoked_at
    assert rc2.reason == rc.reason


def test_metric_event_roundtrip():
    me = MetricEvent(node="n1", event="e1", ts=1.0, ticket_id="t1", details={"x": 1})
    d = me.to_dict()
    me2 = MetricEvent.from_dict(d)
    assert me2.node == me.node
    assert me2.event == me.event
    assert me2.ticket_id == me.ticket_id
    assert me2.details == me.details
