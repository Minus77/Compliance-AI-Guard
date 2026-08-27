"""Local entity resolution over raw text: one person, one canonical id.

Ordering is the whole point (defect D-2). The gateway used to mask as it scanned,
so at masking time it did not yet know that 章三, 章医生 and 章主任 were the same
person and minted three different tokens — which silently breaks every downstream
analysis that reasons about a single HCP.

Resolve first, then mask:

1. roster exact/alias match      -> canonical_id from master data
2. same-surname heuristic        -> case-local canonical_id
3. no grouping possible          -> its own cluster

Two hard constraints:

**No model calls.** This runs on unmasked text, so it is the one component that
sees real names. Sending that to a model would defeat the pseudonymisation
boundary it exists to support. Detection is dictionary + rule based only.

**Resolution failure must never suppress masking.** Masking is the compliance
floor; resolution is an accuracy enhancement. Every detected mention reaches a
cluster, even when grouping is unsafe — worst case each mention becomes its own
cluster and gets its own token.

Same-surname collisions (章三 and 章丽 in one narrative) are marked ``ambiguous``
and deliberately *not* merged: wrongly merging two people attributes one doctor's
opinion to another, which is worse than asking the rep one clarifying question.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Protocol, Sequence, runtime_checkable

from .name_lexicon import NameMention, find_mentions, load_lexicon

ROSTER_CONFIDENCE = 0.99
HEURISTIC_CONFIDENCE = 0.80
AMBIGUOUS_CONFIDENCE = 0.50


@runtime_checkable
class RosterEntry(Protocol):
    """Structural type for master-data subjects (``KnownIdentifier`` satisfies it).

    Declared structurally so this module never imports the gateway, keeping the
    dependency one-way: gateway -> coreference.
    """

    entity_type: str
    canonical_id: str
    values: Sequence[str]


@dataclass
class MentionCluster:
    """A set of mentions believed to refer to one subject."""

    entity_type: str
    canonical_id: str
    resolution_basis: str
    confidence: float
    members: list[NameMention] = field(default_factory=list)
    ambiguous: bool = False

    @property
    def start(self) -> int:
        return min((member.start for member in self.members), default=0)

    def audit_payload(self) -> dict[str, Any]:
        """Audit view of the cluster. Never carries raw names.

        Only offsets, counts and the resolution basis leave this method; the
        member text stays in memory so the ledger cannot become a PII sink.
        """
        return {
            "entity_type": self.entity_type,
            "canonical_id": self.canonical_id,
            "resolution_basis": self.resolution_basis,
            "confidence": self.confidence,
            "ambiguous": self.ambiguous,
            "member_count": len(self.members),
            "member_spans": [f"raw:{m.start}-{m.end}" for m in self.members],
            "member_bases": sorted({m.basis for m in self.members}),
        }


@dataclass
class CoreferenceResult:
    mentions: list[NameMention] = field(default_factory=list)
    clusters: list[MentionCluster] = field(default_factory=list)

    @property
    def ambiguous(self) -> bool:
        return any(cluster.ambiguous for cluster in self.clusters)

    def cluster_for(self, mention: NameMention) -> MentionCluster | None:
        for cluster in self.clusters:
            if any(member.span == mention.span for member in cluster.members):
                return cluster
        return None

    def audit_payload(self) -> dict[str, Any]:
        return {
            "mention_count": len(self.mentions),
            "cluster_count": len(self.clusters),
            "ambiguous": self.ambiguous,
            "clusters": [cluster.audit_payload() for cluster in self.clusters],
        }


def _roster_lookup(roster: Iterable[RosterEntry] | None) -> dict[str, tuple[str, str]]:
    lookup: dict[str, tuple[str, str]] = {}
    for entry in roster or ():
        for value in getattr(entry, "values", ()) or ():
            lookup[value] = (entry.entity_type, entry.canonical_id)
    return lookup


def _roster_hit(mention: NameMention, lookup: dict[str, tuple[str, str]]) -> tuple[str, str] | None:
    """Match a mention against roster values, including its title form.

    A title mention exposes only the surname span ("章" of 章医生), so the alias
    "章医生" is reconstructed before lookup.
    """
    candidates = [mention.text]
    if mention.title:
        candidates.append(f"{mention.text}{mention.title}")
    if mention.prefix:
        candidates.append(f"{mention.prefix}{mention.text}")
    for candidate in candidates:
        hit = lookup.get(candidate)
        if hit is not None:
            return hit
    return None


def _case_local_id(case_id: str | None, index: int) -> str:
    """Case-scoped identity for heuristic clusters.

    Never reused across cases: a heuristic grouping is a local guess and must not
    be promoted into a cross-case identity graph.
    """
    scope = case_id or "adhoc"
    return f"case_local:{scope}:{index}"


def resolve_mentions(
    text: str,
    *,
    known_identifiers: Sequence[RosterEntry] | None = None,
    case_id: str | None = None,
) -> CoreferenceResult:
    """Group person mentions in ``text`` into per-subject clusters."""
    mentions = find_mentions(text)
    if not mentions:
        return CoreferenceResult()

    lookup = _roster_lookup(known_identifiers)
    lexicon = load_lexicon()

    roster_clusters: dict[tuple[str, str], MentionCluster] = {}
    pending: list[NameMention] = []

    for mention in mentions:
        hit = _roster_hit(mention, lookup)
        if hit is None:
            pending.append(mention)
            continue
        entity_type, canonical_id = hit
        key = (entity_type, canonical_id)
        cluster = roster_clusters.get(key)
        if cluster is None:
            cluster = MentionCluster(
                entity_type=entity_type,
                canonical_id=canonical_id,
                resolution_basis="roster",
                confidence=ROSTER_CONFIDENCE,
            )
            roster_clusters[key] = cluster
        cluster.members.append(mention)

    clusters: list[MentionCluster] = list(roster_clusters.values())

    # Heuristic grouping, per (entity_type, surname). Distinct full names under
    # one surname mean distinct people; title-only mentions cannot be attributed
    # to either, so nothing merges and everything is flagged for confirmation.
    grouped: dict[tuple[str, str], list[NameMention]] = {}
    for mention in pending:
        grouped.setdefault((mention.entity_type, mention.surname), []).append(mention)

    local_index = 0
    for (entity_type, _surname), group in sorted(grouped.items(), key=lambda item: item[1][0].start):
        full_names = {m.text for m in group if len(m.text) > len(m.surname)}
        if len(full_names) <= 1:
            local_index += 1
            clusters.append(
                MentionCluster(
                    entity_type=entity_type,
                    canonical_id=_case_local_id(case_id, local_index),
                    resolution_basis="surname_heuristic",
                    confidence=HEURISTIC_CONFIDENCE,
                    members=list(group),
                )
            )
            continue

        by_name: dict[str, list[NameMention]] = {}
        for mention in group:
            by_name.setdefault(mention.text, []).append(mention)
        for name in sorted(by_name, key=lambda key: by_name[key][0].start):
            local_index += 1
            clusters.append(
                MentionCluster(
                    entity_type=entity_type,
                    canonical_id=_case_local_id(case_id, local_index),
                    resolution_basis="surname_heuristic",
                    confidence=AMBIGUOUS_CONFIDENCE,
                    members=list(by_name[name]),
                    ambiguous=True,
                )
            )

    clusters.sort(key=lambda cluster: cluster.start)
    assert sum(len(c.members) for c in clusters) == len(mentions), "resolution dropped a mention"
    _ = lexicon  # lexicon is loaded eagerly so a malformed config fails fast
    return CoreferenceResult(mentions=mentions, clusters=clusters)


__all__ = [
    "AMBIGUOUS_CONFIDENCE",
    "CoreferenceResult",
    "HEURISTIC_CONFIDENCE",
    "MentionCluster",
    "ROSTER_CONFIDENCE",
    "RosterEntry",
    "resolve_mentions",
]
