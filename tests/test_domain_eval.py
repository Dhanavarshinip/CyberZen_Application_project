import pytest
from backend.monitoring.domain_evaluator import DomainEvaluator

def test_domain_evaluator_classifications():
    evaluator = DomainEvaluator()

    # 1. Known safe legitimate domain
    safe_res = evaluator.evaluate_url("https://www.google.com/search?q=cybersecurity")
    assert safe_res["status"] == "SAFE"
    assert safe_res["risk_score"] == 0.0
    assert safe_res["category"] == "No Known Threat"
    assert any("no known threat" in r.lower() for r in safe_res["reasons"])

    # 2. Known dangerous threat signature
    danger_res = evaluator.evaluate_url("https://malware-test.com/sample.exe")
    assert danger_res["status"] == "DANGEROUS"
    assert danger_res["risk_score"] >= 80

    # 3. Piracy domain (policy advisory, distinguished from malware)
    piracy_res = evaluator.evaluate_url("https://1337x.to/torrent/12345/test")
    assert piracy_res["status"] == "SUSPICIOUS"
    assert piracy_res["is_piracy_advisory"] is True
    assert "Piracy" in piracy_res["category"]
    assert any("piracy" in r.lower() for r in piracy_res["reasons"])

    # 4. Ordinary legitimate website with standard domain structure - returns SAFE
    ordinary_res = evaluator.evaluate_url("https://my-local-bakery-shop.org/menu")
    assert ordinary_res["status"] == "SAFE"
    assert ordinary_res["risk_score"] == 0.0
    assert ordinary_res["category"] == "No Known Threat"

    # 5. Genuine unresolvable host / insufficient evidence - returns UNKNOWN with useful reason
    unknown_res = evaluator.evaluate_url("http://invalid_internal_host/")
    assert unknown_res["status"] == "UNKNOWN"
    assert unknown_res["risk_score"] is None
    assert any("insufficient" in r.lower() or "unresolvable" in r.lower() for r in unknown_res["reasons"])
