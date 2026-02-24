from app.database.db import Base, engine
from app.database import models  # noqa: F401
from app.database.seed_cves import seed


if __name__ == "__main__":
    Base.metadata.create_all(bind=engine)
    seed()
