from sqlalchemy.orm import Session
from . import brute_force, token_abuse


# Register detection modules here
DETECTION_RULES = [
    brute_force,
    token_abuse,
]


def run_detection_pipeline(db: Session, event) -> None:
    for rule in DETECTION_RULES:
        rule.evaluate(db, event)
