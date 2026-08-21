"""HTML sanitization and remote-content blocking for the Rendered tab.

Belt AND suspenders: content is bleach-sanitized (no scripts, event
handlers, javascript: URLs, meta refresh) *and* rendered inside a
``sandbox=""`` iframe. Remote content (images, media, CSS fetches) is
rewritten to a local data: placeholder unless the analyst explicitly loads
it for this record, this session.

After bleach, only allowed tags survive as markup; script/iframe/link and
friends are escaped into inert text. The remote-block pass therefore only
ever needs to handle src/background/poster attributes on survivors (img,
table/td background, etc.) and url()/@import inside style attributes.
"""

from __future__ import annotations

import re

import bleach
from bleach.css_sanitizer import CSSSanitizer

ALLOWED_TAGS = [
    "a", "abbr", "acronym", "address", "b", "bdo", "big", "blockquote",
    "br", "caption", "center", "cite", "code", "col", "colgroup", "dd",
    "del", "dfn", "div", "dl", "dt", "em", "font", "h1", "h2", "h3", "h4",
    "h5", "h6", "head", "hr", "html", "i", "img", "ins", "kbd", "li",
    "map", "ol", "p", "pre", "q", "s", "samp", "small", "span", "strike",
    "strong", "style", "sub", "sup", "table", "tbody", "td", "tfoot", "th",
    "thead", "title", "tr", "tt", "u", "ul", "var", "wbr", "body",
]

ALLOWED_ATTRIBUTES: dict[str, list[str]] = {
    "*": [
        "style", "class", "align", "valign", "width", "height", "bgcolor",
        "background", "border", "cellpadding", "cellspacing", "colspan",
        "rowspan", "dir", "lang", "title",
    ],
    "a": ["href", "target", "name", "id", "rel"],
    "img": ["src", "alt", "title", "width", "height", "border", "usemap"],
    "table": ["summary", "rules"],
    "td": ["nowrap", "abbr"],
    "th": ["nowrap", "scope", "abbr"],
    "map": ["name"],
    "area": ["shape", "coords", "href", "alt"],
    "font": ["face", "size", "color"],
    "col": ["span"],
    "colgroup": ["span"],
    "q": ["cite"],
    "blockquote": ["cite"],
}

ALLOWED_PROTOCOLS = ["http", "https", "mailto", "ftp"]

# Sanitize style attributes / <style> blocks: allow common visual properties,
# drop position tricks and anything exotic. url()/@import are handled by the
# remote-content blocker below.
ALLOWED_CSS_PROPERTIES = [
    "background", "background-color", "background-image", "background-repeat",
    "background-position", "background-size", "border", "border-color",
    "border-style", "border-width", "border-radius", "bottom", "color",
    "direction", "display", "float", "font", "font-family", "font-size",
    "font-style", "font-weight", "height", "left", "letter-spacing",
    "line-height", "margin", "max-height", "max-width", "min-height",
    "min-width", "opacity", "padding", "right", "text-align",
    "text-decoration", "text-transform", "top", "vertical-align",
    "white-space", "width", "word-spacing", "word-wrap", "overflow",
    "table-layout", "border-collapse", "border-spacing", "caption-side",
    "empty-cells", "list-style", "list-style-type",
]
_CSS_SANITIZER = CSSSanitizer(allowed_css_properties=ALLOWED_CSS_PROPERTIES)

# 1×1 transparent GIF — remote resources are swapped for this, so the
# rendered view makes zero outbound requests by default.
PLACEHOLDER_IMG = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"

_TAG_RE = re.compile(r"<\s*[a-zA-Z][^>]*>", re.IGNORECASE)
# Attributes that can trigger a fetch when the document renders.
_FETCH_ATTR = re.compile(
    r"""(?ix)\b(src|poster|background|lowsrc|dynsrc)\s*=\s*
    (?:"([^"]*)"|'([^']*)'|([^\s>]+))"""
)
_CSS_URL = re.compile(r"url\s*\(\s*['\"]?\s*[^)]*?['\"]?\s*\)", re.IGNORECASE)
_CSS_IMPORT = re.compile(r"@import[^;]{0,400};?", re.IGNORECASE)


def sanitize_html(html: str, *, block_remote: bool = True) -> str:
    """Sanitize for rendering inside the sandboxed iframe.

    Always strips scripts, event handlers, and javascript: URLs (bleach
    escapes anything not allowed). When ``block_remote`` is set, all
    remote-loadable attribute values and CSS url() references are replaced
    with a local placeholder.
    """
    cleaned = bleach.clean(
        html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        css_sanitizer=_CSS_SANITIZER,
        strip=False,
        strip_comments=True,
    )
    if not block_remote:
        return cleaned
    return _block_remote_content(cleaned)


def _looks_local(value: str) -> bool:
    lowered = value.strip().lower()
    return lowered.startswith(("#", "data:", "mailto:", "cid:"))


def _block_remote_content(html: str) -> str:
    def rewrite_tag(m: re.Match) -> str:
        tag = m.group(0)
        tag = _FETCH_ATTR.sub(_replace_attr_value, tag)
        if re.match(r"<\s*style\b", tag, re.IGNORECASE):
            tag = _CSS_IMPORT.sub("", tag)
        return tag

    result = _TAG_RE.sub(rewrite_tag, html)
    # url()/@import anywhere else (style attributes, <style> bodies).
    result = _CSS_URL.sub(f"url('{PLACEHOLDER_IMG}')", result)
    result = _CSS_IMPORT.sub("", result)
    return result


def _replace_attr_value(m: re.Match) -> str:
    attr = m.group(1).lower()
    value = m.group(2) or m.group(3) or m.group(4) or ""
    if _looks_local(value):
        return m.group(0)
    return f'{attr}="{PLACEHOLDER_IMG}"'
