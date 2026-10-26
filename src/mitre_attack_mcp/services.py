"""Pure business logic. This module must NOT import `mcp`."""

from __future__ import annotations

from . import data


def get_data_stats(*, domain: str | None = None) -> dict | list[dict]:
    """Counts of techniques, groups, software, and mitigations.

    domain: restrict to one domain, or omit for a per-domain breakdown.
    """
    if domain is not None:
        idx = data.get_index(domain)
        return {"domain": domain, **idx.counts()}
    return [{"domain": d, **data.get_index(d).counts()} for d in data.DOMAINS]


def get_technique_by_id(
    attack_id: str,
    *,
    domain: str | None = None,
) -> dict:
    """Look up a technique by ATT&CK ID.

    If `domain` is omitted, all three domains are searched. The returned dict
    includes `domain` so the caller knows where the match came from, and
    `other_domains` lists any additional domains where the same ID also
    exists (ATT&CK IDs are not globally unique across domains).
    """
    matches: list[tuple[str, dict]] = []
    for d in (domain,) if domain else data.DOMAINS:
        obj = data.get_index(d).get_technique(attack_id)
        if obj is not None:
            matches.append((d, obj))

    if not matches:
        where = domain or "any domain"
        raise ValueError(f"Technique {attack_id!r} not found in {where}")

    d, obj = matches[0]
    result = {
        "domain": d,
        "id": data.attack_id_of(obj),
        "name": obj.get("name"),
        "description": (obj.get("description") or "")[:800],
        "tactics": data.tactics_of(obj),
        "platforms": obj.get("x_mitre_platforms", []),
        "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
    }
    if len(matches) > 1:
        result["other_domains"] = [m[0] for m in matches[1:]]
        result["note"] = (
            "This ID also exists in other domains with different content; "
            "pass `domain` to disambiguate."
        )
    return result


def search_techniques(
    keyword: str,
    *,
    domain: str | None = None,
    limit: int = 10,
) -> list[dict]:
    """Search techniques by keyword. `domain=None` searches all domains."""
    domains = (domain,) if domain else data.DOMAINS
    for d in domains:
        if d not in data.DOMAINS:
            raise ValueError(f"Unknown domain {d!r}; expected one of {data.DOMAINS}")

    results: list[dict] = []
    for d in domains:
        hits = data.get_index(d).search_techniques(keyword, limit=limit)
        results.extend(
            {"domain": d, "id": data.attack_id_of(o), "name": o.get("name")}
            for o in hits
        )
        if len(results) >= limit:
            break
    return results[:limit]


def get_group_by_name(
    name: str,
    *,
    domain: str | None = None,
) -> dict:
    """Look up a threat group by name or alias.

    If `domain` is omitted, all three domains are searched; `domain` in the
    result tells the caller where the match was found.
    """
    matches: list[tuple[str, dict]] = []
    for d in (domain,) if domain else data.DOMAINS:
        obj = data.get_index(d).get_group(name)
        if obj is not None:
            matches.append((d, obj))

    if not matches:
        where = domain or "any domain"
        raise ValueError(f"Group {name!r} not found in {where}")

    d, obj = matches[0]
    result = {
        "domain": d,
        "name": obj.get("name"),
        "aliases": obj.get("aliases", []),
        "description": (obj.get("description") or "")[:800],
    }
    if len(matches) > 1:
        result["other_domains"] = [m[0] for m in matches[1:]]
    return result
