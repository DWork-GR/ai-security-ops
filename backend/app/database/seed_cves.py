from sqlalchemy.orm import Session
from app.database.db import SessionLocal
from app.database.models import CVE


CVE_DATA = [
    {
        "cve_id": "CVE-2021-44228",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "description": "Log4Shell — уразливість віддаленого виконання коду в Apache Log4j.",
        "mitigation": "Оновити Log4j до версії 2.17.1 або вище."
    },
    {
        "cve_id": "CVE-2017-0144",
        "cvss": 8.1,
        "severity": "HIGH",
        "description": "EternalBlue — уразливість SMB, що дозволяє віддалене виконання коду.",
        "mitigation": "Встановити оновлення безпеки MS17-010."
    },
    {
        "cve_id": "CVE-2023-34362",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "description": "MOVEit Transfer SQL Injection — масова експлуатація у 2023 році.",
        "mitigation": "Оновити MOVEit Transfer, перевірити логи, змінити облікові дані."
    }
]


def seed():
    db: Session = SessionLocal()

    for item in CVE_DATA:
        exists = db.query(CVE).filter(CVE.cve_id == item["cve_id"]).first()
        if exists:
            continue

        cve = CVE(**item)
        db.add(cve)

    db.commit()
    db.close()

    print("✅ CVE data seeded successfully")


if __name__ == "__main__":
    seed()
