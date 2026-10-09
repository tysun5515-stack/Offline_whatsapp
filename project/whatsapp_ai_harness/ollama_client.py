from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple


class OllamaError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, base_url: str, primary_model: str, fallback_model: str, context_tokens: int):
        self.base_url = base_url
        self.primary_model = primary_model
        self.fallback_model = fallback_model
        self.context_tokens = context_tokens
        self._generation_lock = threading.Lock()
        # Ollama is intentionally a local-only dependency. Windows proxy
        # settings can otherwise route 127.0.0.1 through an enterprise proxy
        # and return a misleading HTTP 403 response.
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _request(self, path: str, payload: Optional[Dict[str, Any]] = None, timeout: int = 300) -> Dict[str, Any]:
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(
            self.base_url + path, data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise OllamaError(f"Ollama request failed: {exc}") from exc

    def status(self) -> Dict[str, Any]:
        try:
            tags = self._request("/api/tags", timeout=3)
            models = tags.get("models", [])
            names = [item.get("name") or item.get("model") for item in models]
            digests = {name: item.get("digest") for name, item in zip(names, models) if name}
            return {"available": True, "models": names, "model_digests": digests}
        except OllamaError as exc:
            return {"available": False, "error": str(exc), "models": [], "model_digests": {}}

    def select_model(self) -> Tuple[str, str]:
        status = self.status()
        if not status["available"]:
            raise OllamaError(status["error"])
        installed = set(status["models"])
        for model in (self.primary_model, self.fallback_model):
            match = model if model in installed else next(
                (name for name in installed if name and name.startswith(model + ":")), None,
            )
            if match:
                digest = status["model_digests"].get(match)
                if not digest:
                    raise OllamaError(f"Ollama did not report a digest for installed model {match!r}.")
                return match, digest
        raise OllamaError(
            f"Neither {self.primary_model!r} nor {self.fallback_model!r} is installed in Ollama."
        )

    def structured(self, prompt: str, schema: Dict[str, Any], temperature: float = 0.0) -> Tuple[Dict[str, Any], str, str]:
        # The target laptop is sized for exactly one local generation at a time.
        with self._generation_lock:
            model, digest = self.select_model()
            schema_prompt = (
                prompt + "\nReturn only one valid JSON object matching this schema exactly:\n" +
                json.dumps(schema, sort_keys=True, separators=(",", ":"))
            )
            options = {"temperature": temperature, "num_ctx": self.context_tokens,
                       "num_predict": 2048}
            if model.startswith("deepseek-r1:"):
                # DeepSeek-R1 may consume the entire output budget in its hidden
                # thinking channel even when think=false. Its published Ollama
                # template supports an empty completed think block, so prefill it
                # and ask the raw generator for the JSON answer directly.
                raw_prompt = (
                    "<｜User｜>" + schema_prompt +
                    "<｜Assistant｜><think>\n\n</think>\n\n"
                )
                response = self._request("/api/generate", {
                    "model": model, "prompt": raw_prompt, "raw": True,
                    "stream": False, "format": "json", "options": options,
                })
                content = response.get("response")
            else:
                response = self._request("/api/chat", {
                    "model": model, "stream": False, "format": "json", "think": False,
                    "messages": [{"role": "user", "content": schema_prompt}],
                    "options": options,
                })
                content = response.get("message", {}).get("content")
        if not isinstance(content, str):
            raise OllamaError("Ollama returned no structured message content")
        try:
            return json.loads(content), model, digest
        except json.JSONDecodeError as exc:
            raise OllamaError("Ollama returned invalid JSON") from exc

