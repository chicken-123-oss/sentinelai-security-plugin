from __future__ import annotations

import hashlib
import hmac
import random
import secrets
import string
from dataclasses import dataclass


def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
    actual_salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), actual_salt.encode("utf-8"), 120_000)
    return actual_salt, digest.hex()


def verify_password(password: str, salt: str, expected_hash: str) -> bool:
    _, actual_hash = hash_password(password, salt)
    return hmac.compare_digest(actual_hash, expected_hash)


def hash_answer(answer: str, salt: str | None = None) -> tuple[str, str]:
    actual_salt = salt or secrets.token_hex(12)
    normalized = normalize_answer(answer)
    digest = hashlib.sha256(f"{actual_salt}:{normalized}".encode("utf-8")).hexdigest()
    return actual_salt, digest


def verify_answer(answer: str, salt: str, expected_hash: str) -> bool:
    _, actual_hash = hash_answer(answer, salt)
    return hmac.compare_digest(actual_hash, expected_hash)


def normalize_answer(answer: str) -> str:
    return "".join(str(answer).strip().lower().split())


@dataclass(frozen=True)
class CaptchaChallenge:
    question: str
    answer: str
    choices: list[str]
    proof: str


def make_captcha_challenge() -> CaptchaChallenge:
    left = random.randint(12, 89)
    right = random.randint(7, 37)
    multiplier = random.randint(2, 5)
    answer = str((left + right) * multiplier)
    distractors = {answer}
    while len(distractors) < 4:
        distractors.add(str(int(answer) + random.choice([-17, -11, -5, 6, 13, 19])))
    choices = list(distractors)
    random.shuffle(choices)
    proof = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    question = f"(({left} + {right}) x {multiplier}) = ?"
    return CaptchaChallenge(question=question, answer=answer, choices=choices, proof=proof)


def validate_new_password(password: str) -> tuple[bool, str]:
    if len(password) < 10:
        return False, "password must be at least 10 characters"
    if not any(char.isdigit() for char in password):
        return False, "password must include a digit"
    if not any(char.isalpha() for char in password):
        return False, "password must include a letter"
    return True, "ok"

