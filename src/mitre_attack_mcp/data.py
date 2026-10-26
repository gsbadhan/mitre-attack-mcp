"""Download and indexing layer for MITRE ATT&CK STIX bundles."""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Iterable

import httpx

logger = logging.getLogger(__name__)

DOMAINS: tuple[str, ...] = ("enterprise-attack", "ics-attack", "mobile-attack")

BASE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/{domain}/{domain}.json"
)

_DEFAULT_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
ENV_DATA_DIR = "MITRE_ATTACK_MCP_DATA_DIR"

DOWNLOAD_TIMEOUT = 120.0
DOWNLOAD_RETRIES = 3
RETRY_BACKOFF = 2.0
CHUNK_SIZE = 1 << 16


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


def data_dir() -> Path:
    override = os.environ.get(ENV_DATA_DIR)
    return Path(override).expanduser() if override else _DEFAULT_DATA_DIR


def file_for(domain: str) -> Path:
    if domain not in DOMAINS:
        raise ValueError(f"Unknown domain {domain!r}; expected one of {DOMAINS}")
    return data_dir() / f"{domain}.json"


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #


def download(domain: str, *, force: bool = False) -> Path:
    if domain not in DOMAINS:
        raise ValueError(f"Unknown domain {domain!r}; expected one of {DOMAINS}")

    dest = file_for(domain)
    if dest.exists() and dest.stat().st_size > 0 and not force:
        logger.info("Using cached %s bundle at %s", domain, dest)
        return dest

    url = BASE_URL.format(domain=domain)
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")

    last_exc: Exception | None = None
    for attempt in range(1, DOWNLOAD_RETRIES + 1):
        try:
            logger.info(
                "Downloading %s (attempt %d/%d)", domain, attempt, DOWNLOAD_RETRIES
            )
            _stream_to_file(url, tmp)
            _validate_stix(tmp)
            tmp.replace(dest)
            logger.info(
                "Saved %s bundle to %s (%d bytes)", domain, dest, dest.stat().st_size
            )
            return dest
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            logger.warning("%s download attempt %d failed: %s", domain, attempt, exc)
            tmp.unlink(missing_ok=True)
            if attempt < DOWNLOAD_RETRIES:
                time.sleep(RETRY_BACKOFF * attempt)

    raise RuntimeError(
        f"Failed to download {domain} bundle after {DOWNLOAD_RETRIES} attempts"
    ) from last_exc


def download_all(
    domains: Iterable[str] | None = None,
    *,
    force: bool = False,
) -> dict[str, Path]:
    domains = tuple(domains or DOMAINS)
    return {d: download(d, force=force) for d in domains}


def _stream_to_file(url: str, dest: Path) -> None:
    with httpx.stream("GET", url, timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0)) or None
        written = 0
        last_bucket = -1
        with dest.open("wb") as fh:
            for chunk in r.iter_bytes(CHUNK_SIZE):
                fh.write(chunk)
                written += len(chunk)
                if total:
                    bucket = (written * 100 // total) // 10
                    if bucket != last_bucket:
                        logger.debug("  ... %d%%", bucket * 10)
                        last_bucket = bucket


def _validate_stix(path: Path) -> None:
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict) or not isinstance(payload.get("objects"), list):
        raise ValueError("Downloaded file is not a STIX bundle")


# --------------------------------------------------------------------------- #
# Indexing
# --------------------------------------------------------------------------- #


class AttackIndex:
    """Indexed view over ONE domain's STIX bundle."""

    def __init__(self, domain: str, objects: Iterable[dict[str, Any]]) -> None:
        self.domain = domain
        self.objects: list[dict[str, Any]] = list(objects)
        self.by_attack_id: dict[str, dict[str, Any]] = {}
        self.by_name: dict[str, dict[str, Any]] = {}
        self.by_type: dict[str, list[dict[str, Any]]] = {}
        self.aliases: dict[str, dict[str, Any]] = {}
        self.by_stix_id: dict[str, dict[str, Any]] = {}
        self._mitigates: dict[str, list[str]] = {}
        self._uses: dict[str, list[str]] = {}
        self._relationship_descriptions: dict[tuple[str, str], str | None] = {}
        self._detection_strategies: dict[str, list[str]] = {}
        self._tactic_id_to_name: dict[str, str] = {}

        for obj in self.objects:
            self._index(obj)

    def _index(self, obj: dict[str, Any]) -> None:
        stix_type = obj.get("type")
        if stix_type:
            self.by_type.setdefault(stix_type, []).append(obj)

        stix_id = obj.get("id")
        if isinstance(stix_id, str):
            self.by_stix_id[stix_id] = obj

        name = obj.get("name")
        if isinstance(name, str) and name:
            self.by_name.setdefault(name.lower(), obj)

        for alias in obj.get("aliases", []) or []:
            if isinstance(alias, str) and alias:
                self.aliases.setdefault(alias.lower(), obj)

        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                self.by_attack_id[ref["external_id"].upper()] = obj

        if stix_type == "relationship" and obj.get("relationship_type") == "mitigates":
            src, tgt = obj.get("source_ref"), obj.get("target_ref")
            if isinstance(src, str) and isinstance(tgt, str):
                self._mitigates.setdefault(tgt, []).append(src)

        if stix_type == "relationship" and obj.get("relationship_type") == "uses":
            src, tgt = obj.get("source_ref"), obj.get("target_ref")
            if isinstance(src, str) and isinstance(tgt, str):
                self._uses.setdefault(tgt, []).append(src)
                self._relationship_descriptions[(src, tgt)] = obj.get("description")

        if stix_type == "relationship" and obj.get("relationship_type") == "detects":
            src, tgt = obj.get("source_ref"), obj.get("target_ref")
            if isinstance(src, str) and isinstance(tgt, str):
                self._detection_strategies.setdefault(tgt, []).append(src)

        if stix_type == "x-mitre-tactic":
            attack_id = attack_id_of(obj)
            shortname = obj.get("x_mitre_shortname")
            if attack_id and shortname:
                self._tactic_id_to_name[attack_id.upper()] = shortname

    def get_technique(self, attack_id: str) -> dict[str, Any] | None:
        obj = self.by_attack_id.get(attack_id.strip().upper())
        return obj if obj and obj.get("type") == "attack-pattern" else None

    def get_group(self, name_or_alias: str) -> dict[str, Any] | None:
        key = name_or_alias.strip().lower()
        obj = self.by_name.get(key) or self.aliases.get(key)
        return obj if obj and obj.get("type") == "intrusion-set" else None

    def search_techniques(
        self, keyword: str, *, limit: int = 10
    ) -> list[dict[str, Any]]:
        kw = keyword.strip().lower()
        if not kw:
            return []
        hits: list[dict[str, Any]] = []
        for obj in self.by_type.get("attack-pattern", []):
            hay = f"{obj.get('name', '')} {obj.get('description', '')}".lower()
            if kw in hay:
                hits.append(obj)
                if len(hits) >= limit:
                    break
        return hits

    def mitigations_for_technique(self, technique_stix_id: str) -> list[dict[str, Any]]:
        """Return mitigation objects linked to a technique via 'mitigates' relationships."""
        source_ids = getattr(self, "_mitigates", {}).get(technique_stix_id, [])
        results: list[dict[str, Any]] = []
        for sid in source_ids:
            obj = self.by_stix_id.get(sid)
            if obj is None or obj.get("type") != "course-of-action":
                continue
            results.append(
                {
                    "id": attack_id_of(obj),
                    "name": obj.get("name"),
                    "description": (obj.get("description") or "")[:600],
                }
            )
        return results

    def procedures_for_technique(self, technique_stix_id: str) -> list[dict[str, Any]]:
        """Return procedure examples for a technique."""
        source_ids = self._uses.get(technique_stix_id, [])
        results: list[dict[str, Any]] = []
        for sid in source_ids:
            actor = self.by_stix_id.get(sid)
            if actor is None:
                continue
            actor_type = actor.get("type")
            if actor_type == "intrusion-set":
                kind = "group"
            elif actor_type in ("malware", "tool"):
                kind = "software"
            else:
                continue
            desc = self._relationship_descriptions.get((sid, technique_stix_id))
            if not desc:
                continue
            results.append(
                {
                    "id": attack_id_of(actor),
                    "name": actor.get("name"),
                    "kind": kind,
                    "aliases": actor.get("aliases", []) if kind == "group" else [],
                    "procedure": desc[:800],
                }
            )
        return results

    def detection_strategies_for_technique(
        self, technique_stix_id: str
    ) -> list[dict[str, Any]]:
        """Return detection strategies and their analytics for a technique."""
        strategy_ids = self._detection_strategies.get(technique_stix_id, [])
        results: list[dict[str, Any]] = []
        for sid in strategy_ids:
            strategy = self.by_stix_id.get(sid)
            if strategy is None or strategy.get("type") != "x-mitre-detection-strategy":
                continue

            analytics = []
            for aid in strategy.get("x_mitre_analytic_refs", []) or []:
                an = self.by_stix_id.get(aid)
                if an and an.get("type") == "x-mitre-analytic":
                    analytics.append(
                        {
                            "id": attack_id_of(an),
                            "name": an.get("name"),
                            "platforms": an.get("x_mitre_platforms", []),
                            "description": (an.get("description") or "")[:600],
                        }
                    )

            results.append(
                {
                    "id": attack_id_of(strategy),
                    "name": strategy.get("name"),
                    "analytics": analytics,
                }
            )
        return results

    def techniques_by_tactic(self, tactic: str) -> list[dict[str, Any]]:
        """Return techniques under a tactic, given its ID (TA0006) or shortname (credential-access)."""
        raw = tactic.strip()
        # If it looks like an ID (TA followed by digits), resolve to shortname
        if raw.upper().startswith("TA") and raw[2:].isdigit():
            target = self._tactic_id_to_name.get(raw.upper())
            if target is None:
                return []  # unknown tactic ID
        else:
            # Treat as a name: "Credential Access" -> "credential-access"
            target = raw.lower().replace(" ", "-").replace("_", "-")

        results: list[dict[str, Any]] = []
        for obj in self.by_type.get("attack-pattern", []):
            phases = obj.get("kill_chain_phases", []) or []
            if any(
                p.get("kill_chain_name") == "mitre-attack"
                and p.get("phase_name") == target
                for p in phases
            ):
                results.append(
                    {
                        "id": attack_id_of(obj),
                        "name": obj.get("name"),
                        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
                        "platforms": obj.get("x_mitre_platforms", []),
                    }
                )
        return results

    def counts(self) -> dict[str, int]:
        return {
            "techniques": len(self.by_type.get("attack-pattern", [])),
            "groups": len(self.by_type.get("intrusion-set", [])),
            "software": len(self.by_type.get("malware", []))
            + len(self.by_type.get("tool", [])),
            "mitigations": len(self.by_type.get("course-of-action", [])),
        }


_indices: dict[str, AttackIndex] = {}


def get_index(domain: str) -> AttackIndex:
    if domain not in DOMAINS:
        raise ValueError(f"Unknown domain {domain!r}; expected one of {DOMAINS}")
    if domain not in _indices:
        path = file_for(domain)
        if not path.exists():
            raise FileNotFoundError(
                f"ATT&CK data for {domain!r} not found at {path}. "
                f"Run the server once with downloads enabled, or set "
                f"{ENV_DATA_DIR} to a directory containing the bundle."
            )
        logger.info("Loading ATT&CK bundle for %s from %s", domain, path)
        with path.open("r", encoding="utf-8") as fh:
            bundle = json.load(fh)
        _indices[domain] = AttackIndex(domain, bundle.get("objects", []))
        logger.info("Indexed %s: %s", domain, _indices[domain].counts())
    return _indices[domain]


# --------------------------------------------------------------------------- #
# STIX helpers
# --------------------------------------------------------------------------- #


def attack_id_of(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def tactics_of(technique: dict[str, Any]) -> list[str]:
    return [
        phase["phase_name"]
        for phase in technique.get("kill_chain_phases", []) or []
        if phase.get("kill_chain_name") == "mitre-attack"
    ]
