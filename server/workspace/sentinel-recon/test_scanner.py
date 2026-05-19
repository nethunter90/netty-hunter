#!/usr/bin/env python3
"""Test suite for Sentinel Recon scanner - validates IDE build pipeline"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from scanner import SentinelRecon


def test_port_parsing():
    s = SentinelRecon("127.0.0.1", ports="80,443,8080")
    assert s.ports == [80, 443, 8080], f"Expected [80, 443, 8080], got {s.ports}"
    print("[PASS] Port list parsing")

    s2 = SentinelRecon("127.0.0.1", ports="20-25")
    assert s2.ports == [20, 21, 22, 23, 24, 25], f"Expected range 20-25, got {s2.ports}"
    print("[PASS] Port range parsing")

    s3 = SentinelRecon("127.0.0.1", ports="22,80-82,443")
    assert s3.ports == [22, 80, 81, 82, 443], f"Expected mixed, got {s3.ports}"
    print("[PASS] Mixed port spec parsing")


def test_service_signatures():
    s = SentinelRecon("127.0.0.1")
    assert s.SERVICE_SIGNATURES[22] == "SSH"
    assert s.SERVICE_SIGNATURES[80] == "HTTP"
    assert s.SERVICE_SIGNATURES[443] == "HTTPS"
    assert s.SERVICE_SIGNATURES[5432] == "PostgreSQL"
    assert s.SERVICE_SIGNATURES[3306] == "MySQL"
    print("[PASS] Service signature mapping")


def test_localhost_scan():
    s = SentinelRecon("127.0.0.1", ports="5000,5432", timeout=0.5, threads=5)
    results = s.scan()
    assert results["target"] == "127.0.0.1"
    assert results["scan_start"] is not None
    assert results["scan_end"] is not None
    assert results["summary"]["total_ports_scanned"] == 2
    assert isinstance(results["open_ports"], list)
    print(f"[PASS] Localhost scan - found {results['summary']['open_ports_found']} open ports")
    return results


def test_json_export(results):
    export_path = "/tmp/sentinel_test_export.json"
    s = SentinelRecon("127.0.0.1")
    s.results = results
    s.export_json(export_path)
    assert os.path.exists(export_path), "Export file not created"
    with open(export_path) as f:
        data = json.load(f)
    assert data["target"] == "127.0.0.1"
    assert "open_ports" in data
    assert "summary" in data
    os.remove(export_path)
    print("[PASS] JSON export")


def test_dedup_ports():
    s = SentinelRecon("127.0.0.1", ports="80,80,443,443,80")
    assert s.ports == [80, 443], f"Expected deduped [80, 443], got {s.ports}"
    print("[PASS] Port deduplication")


def run_all_tests():
    print("=" * 60)
    print("  Sentinel Recon Test Suite")
    print("  Built with Sentinel Primordial IDE")
    print("=" * 60)
    passed = 0
    failed = 0
    tests = [
        ("Port Parsing", test_port_parsing),
        ("Service Signatures", test_service_signatures),
        ("Port Deduplication", test_dedup_ports),
    ]
    for name, test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1

    try:
        results = test_localhost_scan()
        passed += 1
        test_json_export(results)
        passed += 1
    except Exception as e:
        print(f"[FAIL] Scan/Export: {e}")
        failed += 1

    print("=" * 60)
    print(f"  Results: {passed} passed, {failed} failed, {passed + failed} total")
    print("=" * 60)
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
