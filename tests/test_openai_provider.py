"""OpenAI Chat Completions adapter — request/response transforms."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from src.providers import openai_compat


@pytest.mark.asyncio
async def test_anonymize_chat_request_user_message(mock_llm_empty, tmp_path):
    with patch("src.providers.openai_compat.anonymize", new_callable=AsyncMock) as mock_anon:
        mock_anon.side_effect = lambda text, **_: f"[anon]{text}"
        body = {
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "scan 10.10.50.5 at contoso.local"},
                {"role": "assistant", "content": "already surrogate text"},
            ],
        }
        out = await openai_compat.anonymize_chat_request(body)
        assert "[anon]" in out["messages"][0]["content"]
        assert out["messages"][1]["content"] == "already surrogate text"
        mock_anon.assert_awaited_once()


@pytest.mark.asyncio
async def test_anonymize_chat_request_tool_message(mock_llm_empty, tmp_path):
    with patch("src.providers.openai_compat.anonymize", new_callable=AsyncMock) as mock_anon:
        mock_anon.return_value = "[anon]tool output"
        body = {"messages": [{"role": "tool", "content": "nmap found 10.0.0.1", "tool_call_id": "x"}]}
        out = await openai_compat.anonymize_chat_request(body)
        assert out["messages"][0]["content"] == "[anon]tool output"
        mock_anon.assert_awaited_once_with("nmap found 10.0.0.1", is_tool_output=True)


def test_deanonymize_chat_response_content_and_tool_args():
    data = {
        "id": "chatcmpl-test",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": "connect to [HOST_xkqpzt]",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "bash",
                                "arguments": json.dumps({"command": "ssh [USER_rfkw]@[HOST_xkqpzt]"}),
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
    }

    def _replace(s: str) -> str:
        return s.replace("[HOST_xkqpzt]", "dc01.contoso.local").replace("[USER_rfkw]", "jsmith")

    def _replace_deep(obj):
        if isinstance(obj, str):
            return _replace(obj)
        if isinstance(obj, dict):
            return {k: _replace_deep(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_replace_deep(i) for i in obj]
        return obj

    with patch("src.providers.openai_compat.deanonymize", side_effect=_replace), \
         patch("src.providers.openai_compat.deanon_value", side_effect=_replace_deep):
        out = openai_compat.deanonymize_chat_response(data)

    msg = out["choices"][0]["message"]
    assert "dc01.contoso.local" in msg["content"]
    args = json.loads(msg["tool_calls"][0]["function"]["arguments"])
    assert args["command"] == "ssh jsmith@dc01.contoso.local"


def test_upstream_routing_paths():
    from src.providers.routing import upstream_base_for_path

    with patch("src.providers.routing.config") as cfg:
        cfg.ANTHROPIC_API_URL = "https://api.anthropic.com"
        cfg.OPENAI_API_URL = "https://api.openai.com"
        assert upstream_base_for_path("v1/messages") == "https://api.anthropic.com"
        assert upstream_base_for_path("v1/chat/completions") == "https://api.openai.com"
        assert upstream_base_for_path("/v1/chat/completions") == "https://api.openai.com"
