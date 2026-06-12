# SPDX-License-Identifier: BSD-2-Clause
"""Scenario registry for the chaos monkey."""
from __future__ import annotations

import dataclasses
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tools.scenarios.base import Scenario

_REGISTRY: dict[str, type[Scenario]] = {}


def register(cls: type[Scenario]) -> type[Scenario]:
    """Class decorator: add a Scenario subclass to the registry."""
    _REGISTRY[cls.name] = cls
    return cls


def all_scenarios() -> list[type[Scenario]]:
    return list(_REGISTRY.values())


def get_scenario(name: str) -> type[Scenario]:
    if name not in _REGISTRY:
        known = ", ".join(sorted(_REGISTRY))
        raise KeyError(f"Unknown scenario {name!r}. Known: {known}")
    return _REGISTRY[name]


@dataclasses.dataclass
class ScenarioResult:
    name: str
    description: str
    status: str           # "pass" | "fail" | "error" | "skip"
    failures: list[str]
    events: list[dict]    # structured log entries from ctx.log
    duration_s: float
    error: str | None = None

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)
