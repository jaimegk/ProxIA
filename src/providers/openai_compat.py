"""
OpenAI Chat Completions API adapter.

Covers OpenAI, OpenRouter, and other OpenAI-compatible gateways via OPENAI_API_URL.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator

from ..anonymizer import anonymize, deanonymize


def _deanon_value(obj: Any) -> Any:
    if isinstance(obj, str):
        return deanonymize(obj)
    if isinstance(obj, dict):
        return {k: _deanon_value(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deanon_value(i) for i in obj]
    return obj


async def _anon_content_parts(content: Any, *, is_tool_output: bool) -> Any:
    if isinstance(content, str):
        return await anonymize(content, is_tool_output=is_tool_output)
    if isinstance(content, list):
        out = []
        for part in content:
            if not isinstance(part, dict):
                out.append(part)
                continue
            part = dict(part)
            if part.get("type") == "text" and isinstance(part.get("text"), str):
                part["text"] = await anonymize(part["text"], is_tool_output=is_tool_output)
            out.append(part)
        return out
    return content


async def anonymize_chat_request(body: dict) -> dict:
    """Anonymize user/tool text in an OpenAI /v1/chat/completions request."""
    messages = body.get("messages")
    if not isinstance(messages, list):
        return body

    for msg in messages:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "")
        if role == "user":
            msg["content"] = await _anon_content_parts(
                msg.get("content", ""),
                is_tool_output=True,
            )
        elif role == "tool":
            msg["content"] = await _anon_content_parts(
                msg.get("content", ""),
                is_tool_output=True,
            )
        # assistant: already surrogate text from prior turns — skip

    return body


def _deanon_message(message: dict) -> dict:
    content = message.get("content")
    if isinstance(content, str):
        message["content"] = deanonymize(content)

    for tc in message.get("tool_calls") or []:
        fn = tc.get("function")
        if not isinstance(fn, dict):
            continue
        args = fn.get("arguments")
        if isinstance(args, str) and args.strip():
            try:
                parsed = json.loads(args)
                fn["arguments"] = json.dumps(_deanon_value(parsed))
            except json.JSONDecodeError:
                fn["arguments"] = deanonymize(args)
        elif isinstance(args, dict):
            fn["arguments"] = json.dumps(_deanon_value(args))

    return message


def deanonymize_chat_response(data: dict) -> dict:
    """Deanonymize assistant text and tool call arguments in a chat completion."""
    for choice in data.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        msg = choice.get("message")
        if isinstance(msg, dict):
            choice["message"] = _deanon_message(msg)
    return data


async def emit_chat_completion_sse(data: dict) -> AsyncIterator[str]:
    """
    Re-emit a complete chat completion as OpenAI-style SSE chunks.
    Upstream is called with stream=false so the full body can be deanonymized first.
    """
    completion_id = data.get("id", "chatcmpl-dontfeedtheai")
    model = data.get("model", "")
    choices = data.get("choices") or []
    if not choices:
        yield "data: [DONE]\n\n"
        return

    choice0 = choices[0]
    message = choice0.get("message") or {}
    finish_reason = choice0.get("finish_reason") or "stop"
    content = message.get("content") or ""

    def _chunk(delta: dict, *, finish: str | None = None) -> str:
        payload: dict[str, Any] = {
            "id": completion_id,
            "object": "chat.completion.chunk",
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "delta": delta,
                    "finish_reason": finish,
                }
            ],
        }
        return f"data: {json.dumps(payload)}\n\n"

    yield _chunk({"role": "assistant"})

    chunk_size = 32
    for i in range(0, len(content), chunk_size):
        yield _chunk({"content": content[i : i + chunk_size]})

    tool_calls = message.get("tool_calls") or []
    if tool_calls:
        yield _chunk({"tool_calls": tool_calls})

    yield _chunk({}, finish=finish_reason)
    yield "data: [DONE]\n\n"
