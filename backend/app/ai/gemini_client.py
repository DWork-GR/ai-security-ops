import json
from urllib import error, request

from app.config import (
    GEMINI_API_KEY,
    LLM_PROVIDER,
    OLLAMA_API_KEY,
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
        "This is a defensive blue-team incident response task.\n"
        "Provide only detection, containment, and remediation guidance.\n"
        "Do not provide offensive instructions.\n"
        "Use only the alerts below. Keep output concise and practical.\n"
        "Do not include disclaimers about real-time data, model limits, or knowledge cutoff.\n"
        "Return plain text in this exact structure:\n\n"
        "[EN] LLM Enrichment\n"
        "Threat Analysis:\n"
        "- ...\n"
        "Potential Risks:\n"
        "- ...\n"
        "Response Actions:\n"
        "- ...\n\n"
        "[UK] LLM Збагачення\n"
        "Аналіз Загрози:\n"
        "- ...\n"
        "Потенційні Ризики:\n"
        "- ...\n"
        "Дії Реагування:\n"
        "- ...\n\n"
        "Limit each section to 2-3 bullets.\n\n"
        f"Alerts:\n{chr(10).join(alerts)}\n"
    )


def _clean_llm_output(text: str) -> str:
    if not text:
        return ""

    banned_fragments = [
        "knowledge cutoff",
        "i can't provide real-time",
        "i cannot provide real-time",
        "i don't have access to real-time",
        "i do not have access to real-time",
        "i can't provide dynamic information",
    ]

    kept_lines = []
    for line in text.splitlines():
        lower_line = line.strip().lower()
        if any(fragment in lower_line for fragment in banned_fragments):
            continue
        kept_lines.append(line.rstrip())

    cleaned = "\n".join(kept_lines).strip()
    if not cleaned:
        return text.strip()
    return cleaned


def _looks_like_refusal(text: str) -> bool:
    lowered = text.lower()
    refusal_markers = [
        "i can't assist",
        "i cannot assist",
        "can't help with",
        "cannot help with",
        "can't provide guidance",
        "cannot provide guidance",
        "malicious purposes",
        "i'm unable to help",
        "i am unable to help",
    ]
    return any(marker in lowered for marker in refusal_markers)


def _analyze_with_ollama(alerts: list[str]) -> str:
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": _build_prompt(alerts),
        "stream": False,
        "options": {"temperature": 0.2, "num_predict": 500},
    }
    req = request.Request(
        f"{OLLAMA_BASE_URL}/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if OLLAMA_API_KEY:
        req.add_header("Authorization", f"Bearer {OLLAMA_API_KEY}")
    try:
        with request.urlopen(req, timeout=45) as response:
            body = response.read().decode("utf-8")
        parsed = json.loads(body)
        text = _clean_llm_output(parsed.get("response", "").strip())
        if not text:
            return (
                "[EN] LLM Enrichment\n"
                "- Unavailable: Ollama returned an empty response.\n\n"
                "[UK] LLM Збагачення\n"
                "- Недоступно: Ollama повернула порожню відповідь."
            )
        if _looks_like_refusal(text):
            return (
                "[EN] LLM Enrichment\n"
                "- Unavailable: model refused this request.\n"
                "- Rule-based EN+UK analysis is shown above.\n\n"
                "[UK] LLM Збагачення\n"
                "- Недоступно: модель відхилила цей запит.\n"
                "- Вище показано rule-based аналіз EN+UK."
            )
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
        text = _clean_llm_output(response.text or "")
        return text or "LLM returned an empty response."
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
        return (
            "[EN] LLM Enrichment\n"
            "- Disabled: provider is set to none.\n\n"
            "[UK] LLM Збагачення\n"
            "- Вимкнено: провайдер встановлено в none."
        )
    if provider == "ollama":
        return _analyze_with_ollama(alerts)
    if provider == "gemini":
        return _analyze_with_gemini(alerts)

    return (
        "LLM enrichment disabled: unknown provider. "
        "Supported values: none, ollama, gemini."
    )
