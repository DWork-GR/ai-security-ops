from app.database.db import get_connection


def seed():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT OR IGNORE INTO cve VALUES (
            'CVE-2021-44228',
            10.0,
            'Log4Shell — критична уразливість у Log4j.',
            'Оновити Log4j до версії 2.17.1 або вище.'
        )
    """)

    conn.commit()
    conn.close()


if __name__ == "__main__":
    seed()
