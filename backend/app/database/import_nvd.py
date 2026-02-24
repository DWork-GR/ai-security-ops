import argparse

from app.database.db import Base, SessionLocal, engine
from app.services.nvd_import_service import import_nvd_json


def main():
    parser = argparse.ArgumentParser(description="Import CVEs from local NVD JSON file")
    parser.add_argument("--file", required=True, help="Path to NVD JSON file")
    parser.add_argument(
        "--default-mitigation",
        default="Review vendor advisory, apply patches, and validate mitigations.",
        help="Fallback mitigation text",
    )
    args = parser.parse_args()

    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        result = import_nvd_json(
            db,
            file_path=args.file,
            default_mitigation=args.default_mitigation,
        )
        print(
            "NVD import completed:",
            f"imported_total={result['imported_total']}",
            f"created={result['created']}",
            f"updated={result['updated']}",
            f"skipped={result['skipped']}",
        )
    finally:
        db.close()


if __name__ == "__main__":
    main()
