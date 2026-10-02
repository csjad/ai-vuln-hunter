"""Payload 存储：按漏洞类型存取、记录成功率，支持学习引擎调权。"""
from __future__ import annotations

import json
import threading
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from config import settings


class PayloadStore:
    """可持久化的 Payload 仓库，记录每个 payload 的命中/误报统计。"""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or (settings.kb_dir / "payloads.json")
        self._lock = threading.Lock()
        # {vuln_type: [{"payload": str, "vector": str, "hits": int, "miss": int}]}
        self._data: Dict[str, List[dict]] = defaultdict(list)
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                with self.path.open("r", encoding="utf-8") as f:
                    raw = json.load(f)
                for k, v in raw.items():
                    self._data[k] = v
            except (json.JSONDecodeError, OSError):
                pass

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)

    def add(self, vuln_type: str, payload: str, vector: str = "query") -> None:
        with self._lock:
            for item in self._data[vuln_type]:
                if item["payload"] == payload:
                    return
            self._data[vuln_type].append(
                {"payload": payload, "vector": vector, "hits": 0, "miss": 0}
            )

    def get(self, vuln_type: str) -> List[dict]:
        return list(self._data.get(vuln_type, []))

    def record_hit(self, vuln_type: str, payload: str) -> None:
        with self._lock:
            for item in self._data[vuln_type]:
                if item["payload"] == payload:
                    item["hits"] += 1
                    return

    def record_miss(self, vuln_type: str, payload: str) -> None:
        with self._lock:
            for item in self._data[vuln_type]:
                if item["payload"] == payload:
                    item["miss"] += 1
                    return

    def ranked(self, vuln_type: str, limit: int = 20) -> List[dict]:
        """按成功率排序返回 payload。"""
        items = self.get(vuln_type)
        def score(it: dict) -> float:
            total = it["hits"] + it["miss"]
            if total == 0:
                return 0.0
            return it["hits"] / total
        return sorted(items, key=score, reverse=True)[:limit]
