"""Tolerant parsing for JSON emitted by a chat-completions provider."""

from __future__ import annotations

import json
import re
from typing import Any


# Models sometimes wrap JSON in a markdown fence or add introductory prose.
# Tolerating only framing keeps malformed output a fail-safe case.
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """Pull the first JSON object out of a model message.

    Real models are inconsistent about output framing even at temperature 0: some
    return a bare object, some wrap it in a markdown fence, and some prepend a
    line of prose. Rejecting those would turn a formatting quirk into a
    ``FAILED_SAFE`` case and send perfectly good checks to human review, so the
    object is located explicitly.

    Only *framing* is tolerated. Anything that is not a JSON object still fails,
    and the caller still fails safe: this never guesses at content.
    """
    candidate = text.strip()

    # 1. Already a bare object.
    if candidate.startswith("{"):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            return parsed

    # 2. Fenced anywhere in the message.
    for match in _FENCE_RE.finditer(candidate):
        try:
            parsed = json.loads(match.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed

    # 3. A top-level array is a contract violation, not a framing quirk. Digging
    #    the first element out of it would invent an object the model never
    #    asserted, so it is refused and the caller fails safe.
    if candidate.startswith("["):
        return None

    # 4. Prose, then an object. Scan for the first balanced brace run, honouring
    #    string literals and escapes so braces inside values do not confuse it.
    start = candidate.find("{")
    while start != -1:
        # An object that is an element of an array is not the top-level result.
        prefix = candidate[:start].rstrip()
        if prefix.endswith("["):
            start = candidate.find("{", start + 1)
            continue
        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(candidate)):
            char = candidate[index]
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    try:
                        parsed = json.loads(candidate[start : index + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(parsed, dict):
                        return parsed
                    break
        start = candidate.find("{", start + 1)

    return None
