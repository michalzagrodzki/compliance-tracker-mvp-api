# core/security_utils.py
from __future__ import annotations
from decimal import Decimal
from typing import Optional, Dict, Any, Protocol
from datetime import datetime, timedelta
from fastapi import HTTPException, Request
import hashlib, json, unicodedata, uuid, datetime

MAX_USER_AGENT_LEN = 256

def _normalize_for_fingerprint(o):
    if isinstance(o, str):
        # Normalize and trim, but DO NOT collapse internal whitespace by default
        return unicodedata.normalize("NFKC", o).strip()
    if isinstance(o, (int, float, bool)) or o is None:
        return o
    if isinstance(o, Decimal):
        # Prefer str to avoid float rounding artifacts
        return str(o)
    if isinstance(o, (datetime.datetime, datetime.date)):
        return o.isoformat()
    if isinstance(o, uuid.UUID):
        return str(o)
    if isinstance(o, dict):
        # Ensure string keys; sort for stability
        return {str(k): _normalize_for_fingerprint(v) for k, v in sorted(o.items(), key=lambda kv: str(kv[0]))}
    if isinstance(o, (list, tuple)):
        return [_normalize_for_fingerprint(x) for x in o]
    return str(o)

def stable_fingerprint(obj: dict) -> str:
    payload = json.dumps(_normalize_for_fingerprint(obj),
                         sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def normalize_user_agent(ua: Optional[str]) -> Optional[str]:
    if not ua:
        return None
    ua = ua.strip().replace("\x00", "")
    return ua[:MAX_USER_AGENT_LEN]

def ensure_json_request(request: Request) -> None:
    ctype = request.headers.get("content-type", "")
    if not ctype.startswith("application/json"):
        raise HTTPException(status_code=415, detail="Unsupported Media Type. Use application/json.")

def compute_fingerprint(payload: Dict[str, Any]) -> str:
    def convert_for_json(obj):
        """Convert non-JSON-serializable objects to strings"""
        if hasattr(obj, '__str__'):
            return str(obj)
        raise TypeError(f'Object of type {obj.__class__.__name__} is not JSON serializable')
    
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=convert_for_json)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class IdempotencyRepo(Protocol):
    def get(self, key: str) -> Optional[Dict[str, Any]]: ...
    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None: ...

class InMemoryIdempotencyRepo:
    def __init__(self) -> None:
        self._store: Dict[str, Dict[str, Any]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        item = self._store.get(key)
        if not item:
            return None
        if item["expires_at"] < datetime.utcnow():
            self._store.pop(key, None)
            return None
        return item["value"]

    def set(self, key: str, value: Dict[str, Any], ttl_seconds: int) -> None:
        self._store[key] = {
            "value": value,
            "expires_at": datetime.utcnow() + timedelta(seconds=ttl_seconds),
        }

def require_idempotency(repo: IdempotencyRepo, idempotency_key: Optional[str], fingerprint: str
) -> Optional[Dict[str, Any]]:
    if not idempotency_key:
        return None
    cached = repo.get(idempotency_key)
    if cached and cached.get("fingerprint") == fingerprint:
        return cached["response"]
    return None

def store_idempotency(repo: IdempotencyRepo, idempotency_key: Optional[str], fingerprint: str,
                      response: Dict[str, Any], ttl_seconds: int = 24 * 3600) -> None:
    if not idempotency_key:
        return
    repo.set(idempotency_key, {"fingerprint": fingerprint, "response": response}, ttl_seconds)
