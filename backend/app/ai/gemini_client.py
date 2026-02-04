import os
from dotenv import load_dotenv
from google import genai

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
if not API_KEY:
    raise RuntimeError("GEMINI_API_KEY not found")

client = genai.Client(api_key=API_KEY)


def analyze_security_incidents(alerts: list[str]) -> str:
    prompt = (
        "You are a cybersecurity analyst (SOC Level 2).\n\n"
        "Analyze the following IDS (Snort) critical alerts:\n\n"
        + "\n".join(alerts)
        + "\n\n"
        "Provide:\n"
        "1. Short threat analysis\n"
        "2. Potential risks\n"
        "3. Recommended response actions\n"
        "Write clearly and concisely."
    )

    try:
        response = client.models.generate_content(
            model="models/gemini-2.0-flash",
            contents=prompt
        )
        return response.text or "⚠️ Gemini returned an empty response."

    except Exception as e:
        return f"❌ Gemini error: {e}"
