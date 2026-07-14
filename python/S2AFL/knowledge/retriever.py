"""
Compatibility wrapper around the unified S2AFL knowledge graph.
"""

from .codeql_bridge import S2AFLKnowledgeGraph


class KnowledgeBase(S2AFLKnowledgeGraph):
    """Backward-compatible entrypoint for KG queries."""

    @property
    def protocols(self) -> list[str]:
        protocols = set()
        for facts in self._facts_by_impl.values():
            for fact in facts:
                if fact.get("protocol"):
                    protocols.add(fact["protocol"])
        return sorted(protocols)

    def __len__(self) -> int:
        return sum(len(facts) for facts in self._facts_by_impl.values())

    def __repr__(self) -> str:
        return f"<KnowledgeBase implementations={self.implementations} facts={len(self)}>"
