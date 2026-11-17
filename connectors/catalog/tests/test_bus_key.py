"""Event-bus keys (P7 throughput): ordered streams per instance, telemetry spread per message."""

from nocsoc_connectors import bus_key, is_telemetry_stream


def test_telemetry_streams_are_spread_per_message() -> None:
    assert is_telemetry_stream("splunk", "auth_events") and is_telemetry_stream("prometheus", "metrics")
    a = bus_key("t", "i", "prometheus", "metrics", "e1")
    b = bus_key("t", "i", "prometheus", "metrics", "e2")
    assert a != b and a.startswith(b"t:i:")


def test_ordered_streams_keep_one_key_per_instance() -> None:
    assert not is_telemetry_stream("prometheus", "alerts")
    assert bus_key("t", "i", "prometheus", "alerts", "e1") == bus_key("t", "i", "prometheus", "alerts", "e2") == b"t:i"
    assert bus_key("t", "i", "unknown.connector", "x", "e1") == b"t:i"
