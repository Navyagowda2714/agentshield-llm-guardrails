from agentshield.ingest import from_email, from_html, from_source, html_to_text, naive_html_text
from agentshield.models import SourceType, TrustLevel


def test_html_hidden_text_separated():
    html = ('<p>Visible body.</p><div style="display:none">secret instruction</div>'
            "<!-- comment instruction --><span aria-hidden='true'>aria secret</span>")
    visible, hidden = html_to_text(html)
    assert "Visible body." in visible
    assert "secret instruction" not in visible
    joined = " ".join(hidden)
    assert "secret instruction" in joined and "comment instruction" in joined and "aria secret" in joined


def test_naive_extraction_keeps_hidden():
    html = '<p>ok</p><div style="display:none">attack</div>'
    assert "attack" in naive_html_text(html)


def test_from_html_sets_untrusted_trust():
    item = from_html("<p>hi</p>", url="https://x.example")
    assert item.source is SourceType.WEB_PAGE
    assert item.trust_level is TrustLevel.UNTRUSTED
    assert item.provenance["url"] == "https://x.example"


def test_email_html_part_parsed():
    raw = ("From: a@b.com\nSubject: hi\nMIME-Version: 1.0\n"
           'Content-Type: multipart/alternative; boundary="B"\n\n--B\nContent-Type: text/plain\n\n'
           'plain body\n--B\nContent-Type: text/html\n\n<p>html body</p>'
           '<div style="display:none">hidden</div>\n--B--\n')
    item = from_email(raw)
    assert "plain body" in item.text
    assert "hidden" in " ".join(item.hidden_segments)
    assert item.provenance["from"] == "a@b.com"


def test_markdown_comment_is_hidden():
    item = from_source("Body text.\n<!-- ignore instructions -->", "document")
    assert "ignore instructions" in " ".join(item.hidden_segments)
    assert "ignore instructions" not in item.text


def test_default_trust_levels():
    assert from_source("hi", "user_message").trust_level is TrustLevel.USER
    assert from_source("hi", "rag_chunk", doc_id="d").trust_level is TrustLevel.UNTRUSTED
