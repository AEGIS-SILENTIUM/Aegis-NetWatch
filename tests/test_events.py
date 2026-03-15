"""NetWatch — Event Bus Tests"""
import threading
import time
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.events import EventBus


def test_subscribe_and_publish():
    bus     = EventBus()
    results = []
    bus.subscribe("test.event", lambda d: results.append(d))
    bus.publish("test.event", {"key": "value"})
    time.sleep(0.1)
    assert len(results) == 1
    assert results[0]["key"] == "value"


def test_multiple_subscribers():
    bus = EventBus()
    r1, r2 = [], []
    bus.subscribe("ev", lambda d: r1.append(d))
    bus.subscribe("ev", lambda d: r2.append(d))
    bus.publish("ev", "hello")
    time.sleep(0.1)
    assert len(r1) == 1
    assert len(r2) == 1


def test_no_subscribers():
    bus = EventBus()
    bus.publish("nobody.listening", {"data": 123})  # Should not raise


def test_handler_exception_isolation():
    bus     = EventBus()
    results = []
    def bad_handler(_): raise RuntimeError("boom")
    def good_handler(d): results.append(d)
    bus.subscribe("ev", bad_handler)
    bus.subscribe("ev", good_handler)
    bus.publish("ev", "test")
    time.sleep(0.1)
    assert len(results) == 1  # good handler still ran
