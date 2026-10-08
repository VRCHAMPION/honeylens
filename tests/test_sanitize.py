from honeylens.pipeline.sanitize import FIELD_LIMITS, clean_ip, clean_port, clean_text, defang, mask_ip


def test_strips_ansi_and_controls():
    raw = "\x1b[31mred\x1b[0m\x00\x07 text\x1b]0;title\x07\x9b"
    assert clean_text(raw) == "red text"


def test_newlines_become_visible_marker():
    assert clean_text("a\r\nb\nc") == "a ⏎ b ⏎ c"


def test_length_limit():
    out = clean_text("x" * 100000, "command")
    assert len(out) == FIELD_LIMITS["command"]
    assert out.endswith("…")


def test_non_string_and_none():
    assert clean_text(None) == ""
    assert clean_text(123) == "123"


def test_html_is_kept_as_text_for_later_escaping():
    # We do NOT escape at storage time; Jinja2/Grafana escape at display time.
    assert clean_text("<script>alert(1)</script>") == "<script>alert(1)</script>"


def test_ip_and_port_validation():
    assert clean_ip("203.0.113.5") == "203.0.113.5"
    assert clean_ip("2001:db8::1") == "2001:db8::1"
    for bad in ("999.1.1.1", "'; DROP TABLE x;--", None, 5, "1" * 100):
        assert clean_ip(bad) is None
    assert clean_port("22") == 22
    assert clean_port(70000) is None
    assert clean_port(True) is None


def test_defang_and_mask():
    assert defang("http://198.51.100.7/x.sh") == "hxxp[://]198[.]51[.]100[.]7/x[.]sh"
    assert mask_ip("203.0.113.45") == "203.0.113.x"
    assert mask_ip("2001:db8::1").endswith("(masked)")
    assert mask_ip("nonsense") == "x.x.x.x"
