import json
from urllib import error, request

from app.config import (
    GEMINI_API_KEY,
    LLM_PROVIDER,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
)


def _has_real_api_key(value: str) -> bool:
    if not value:
        return False
    lowered = value.strip().lower()
    if lowered.startswith("replace_with"):
        return False
    return True


def _build_prompt(alerts: list[str]) -> str:
    return (
        "You are a cybersecurity analyst (SOC Level 2).\n"
        "Analyze the following IDS critical alerts and provide:\n"
        "1) short threat analysis\n"
        "2) potential risks\n"
        "3) response actions\n\n"
        f"Alerts:\n{chr(10).join(alerts)}"
    )


def _analyze_with_ollama(alerts: list[str]) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": _build_prompt(alerts),
        "stream": False,
    }
    req = request.Request(
        f"{OLLAMA_BASE_URL}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=45) as response:
            body = response.read().decode("utf-8")
        parsed = json.loads(body)
        text = parsed.get("response", "").strip()
        if not text:
            return "LLM enrichment unavailable: Ollama returned an empty response."
        return text
    except error.HTTPError as exc:
        return f"LLM enrichment unavailable: Ollama HTTP {exc.code}."
    except Exception as exc:
        return f"LLM enrichment unavailable: Ollama is not reachable ({exc})."


def _analyze_with_gemini(alerts: list[str]) -> str:
    if not _has_real_api_key(GEMINI_API_KEY):
        return "LLM enrichment disabled: valid GEMINI_API_KEY is not configured."

    try:
        from google import genai
    except Exception as exc:
        return f"LLM enrichment unavailable: {exc}"

    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(
            model="models/gemini-2.0-flash",
            contents=_build_prompt(alerts),
        )
        return response.text or "LLM returned an empty response."
    except Exception as exc:
        error_text = str(exc)
        if "API_KEY_INVALID" in error_text or "API key not valid" in error_text:
            return "LLM enrichment disabled: GEMINI_API_KEY is invalid."
        if "PERMISSION_DENIED" in error_text:
            return "LLM enrichment disabled: key does not have required permissions."
        if "RESOURCE_EXHAUSTED" in error_text or "quota" in error_text.lower():
            return "LLM enrichment unavailable: Gemini quota exceeded."
        return f"LLM enrichment unavailable: {error_text}"


def analyze_security_incidents(alerts: list[str]) -> str:
    provider = (LLM_PROVIDER or "none").lower()

    if provider == "none":
        return "LLM enrichment disabled: provider is set to none."
    if provider == "ollama":
        return _analyze_with_ollama(alerts)
    if provider == "gemini":
        return _analyze_with_gemini(alerts)

    return (
        "LLM enrichment disabled: unknown provider. "
        "Supported values: none, ollama, gemini."
    )
