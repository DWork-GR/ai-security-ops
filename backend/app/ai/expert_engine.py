def analyze_alerts_expert(alerts: list[str]) -> str:
    analysis = []
    recommendations = []

    for alert in alerts:
        if "SQL Injection" in alert:
            analysis.append(
                "Виявлено ознаки <b>SQL Injection</b> — атаки на рівні прикладної логіки."
            )
            recommendations.extend([
                "Тимчасово обмежити доступ з підозрілих IP",
                "Перевірити журнали доступу веб-сервера",
                "Оновити ORM або фільтрацію введення"
            ])

    if not analysis:
        return "<b>Критичних загроз не виявлено.</b>"

    result = "<b>📊 Аналітичний висновок (експертна система):</b><br><br>"
    for a in analysis:
        result += f"• {a}<br>"

    result += "<br><b>🔧 Рекомендації:</b><br>"
    for r in set(recommendations):
        result += f"• {r}<br>"

    return result
