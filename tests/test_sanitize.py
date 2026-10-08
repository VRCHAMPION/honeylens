from honeylens.pipeline.sanitize import (
    FIELD_LIMITS,
    clean_ip,
    clean_port,
    clean_text,
    defang,
    mask_ip,
    mask_ips_in_text,
)


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


def test_unicode_format_characters_are_stripped():
    # RIGHT-TO-LEFT OVERRIDE, ZERO WIDTH SPACE, LEFT-TO-RIGHT ISOLATE, POP ISOLATE, BOM
    raw = "rm\u202e -rf\u200b /tmp\u2066x\u2069\ufeff"
    assert clean_text(raw) == "rm -rf /tmpx"
    # ordinary non-ASCII text is kept
    assert clean_text("caf\u00e9 \u4f60\u597d \u23ce") == "caf\u00e9 \u4f60\u597d \u23ce"


def test_mask_ips_in_text_plain_and_defanged():
    assert mask_ips_in_text("wget http://198.51.100.23/x.sh") == "wget http://198.51.100.x/x.sh"
    assert mask_ips_in_text("hxxp[://]198[.]51[.]100[.]23/bins/x86[.]sh") == "hxxp[://]198[.]51[.]100[.]x/bins/x86[.]sh"
    assert mask_ips_in_text("1(.)2(.)3(.)4 and 9[dot]8[dot]7[dot]6") == "1(.)2(.)3(.)x and 9[dot]8[dot]7[dot]x"
    assert mask_ips_in_text("ping ::ffff:203.0.113.9") == "ping ::ffff:203.0.113.x"


def test_mask_ips_in_text_ipv6():
    out = mask_ips_in_text("curl http://[2001:db8:85a3::8a2e:370:7334]:8080/a")
    assert "7334" not in out and "2001:db8:85a3::/48(masked)" in out


def test_mask_ips_in_text_leaves_non_ips_alone():
    for text in ("echo 12:30:45", "std::cout", "version 1.2.3", "10.0.0.256", "", "uname -a"):
        assert mask_ips_in_text(text) == text
