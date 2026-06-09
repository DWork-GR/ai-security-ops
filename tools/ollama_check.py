import json
import os
import urllib.error
import urllib.request
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    _load_dotenv(Path(".env"))
    base_url = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
    model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
    provider = os.getenv("LLM_PROVIDER", "none")

    print(f"LLM_PROVIDER={provider}")
    print(f"OLLAMA_BASE_URL={base_url}")
    print(f"OLLAMA_MODEL={model}")

    try:
        tags = _get_json(f"{base_url}/api/tags")
    except urllib.error.URLError as exc:
        print(f"ollama_api=unreachable ({exc})")
        return 1

    models = [item.get("name") for item in tags.get("models", []) if item.get("name")]
    print("ollama_api=ok")
    print(f"models={models if models else 'none'}")
    print(f"configured_model_present={model in models}")
    return 0 if model in models else 2


if __name__ == "__main__":
    raise SystemExit(main())
