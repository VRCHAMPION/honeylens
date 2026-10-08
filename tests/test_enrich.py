from honeylens.enrich.geo import Enricher, GeoInfo, IPInfoProvider, MMDBProvider, classify_ip, demo_geo


def test_classify():
    assert classify_ip("198.51.100.4") == "documentation"
    assert classify_ip("10.1.2.3") == "private"
    assert classify_ip("127.0.0.1") == "private"
    assert classify_ip("224.0.0.1") == "reserved"
    assert classify_ip("8.8.8.8") == "public"
    assert classify_ip("bogus") == "invalid"


def test_demo_is_deterministic_and_labelled():
    a, b = demo_geo("203.0.113.7"), demo_geo("203.0.113.7")
    assert a == b and a.source == "demo" and "simulated" in a.as_org
    assert 64512 <= a.asn <= 65534


class FakeProvider:
    name = "fake"

    def __init__(self):
        self.calls = 0

    def lookup(self, ip):
        self.calls += 1
        return GeoInfo(ip=ip, country_code="NL", country="Netherlands", asn=1, as_org="X", source="fake")


def test_chain_order_and_private_never_looked_up():
    fake = FakeProvider()
    e = Enricher([fake])
    assert e.lookup("10.0.0.1").is_private and fake.calls == 0
    assert e.lookup("198.51.100.1").source == "demo" and fake.calls == 0
    assert e.lookup("8.8.8.8").source == "fake" and fake.calls == 1


def test_missing_mmdb_and_api_disabled():
    m = MMDBProvider("/nonexistent/city.mmdb", "")
    assert not m.available and m.lookup("8.8.8.8") is None
    assert IPInfoProvider("").lookup("8.8.8.8") is None
    assert IPInfoProvider("token").lookup("10.0.0.1") is None  # never sends private IPs
