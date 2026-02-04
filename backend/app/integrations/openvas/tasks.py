import uuid


def start_scan(ip: str):
    return {
        "task_id": str(uuid.uuid4()),
        "target": ip,
        "status": "running"
    }
