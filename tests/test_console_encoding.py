"""Banner glyph fallback for terminals that can't encode emoji (legacy Windows cp1252 consoles)."""

from __future__ import annotations

import io

from dbx_nwp_helper import console


class _Cp1252Stream(io.TextIOWrapper):
    pass


def test_utf_stream_keeps_unicode_glyphs():
    stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    assert console._stream_carries_unicode(stream) is True
    assert stream.errors == "strict"  # untouched


def test_cp1252_stream_is_switched_to_replace_errors():
    stream = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")
    assert console._stream_carries_unicode(stream) is False
    assert stream.errors == "replace"
    stream.write("ℹ️ ok")  # would raise UnicodeEncodeError on a strict cp1252 stream
    stream.flush()


def test_stream_without_encoding_or_reconfigure_is_treated_as_ascii():
    class Bare:
        pass

    assert console._stream_carries_unicode(Bare()) is False


def test_banner_uses_ascii_glyphs_when_unicode_unavailable(monkeypatch, capsys):
    monkeypatch.setattr(console, "UNICODE_GLYPHS", False)
    console.banner("warn", "careful")
    console.banner("success", "done")
    out = capsys.readouterr().out
    assert "[!] careful" in out
    assert "[ok] done" in out
    assert "⚠️" not in out and "✅" not in out


def test_banner_uses_unicode_glyphs_when_available(monkeypatch, capsys):
    monkeypatch.setattr(console, "UNICODE_GLYPHS", True)
    console.banner("danger", "stop")
    assert "⛔ stop" in capsys.readouterr().out
