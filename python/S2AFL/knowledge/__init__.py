"""S2AFL knowledge package root.

Keep package initialization lightweight while exposing the public helpers used
by the release CLI.
"""

from .codeql_bridge import S2AFLKnowledgeGraph as KnowledgeBase
from .codeql_import import convert_file as convert_codeql_file
from .codeql_import import import_codeql_for_implementation
from .dynamic_taint import import_all_dynamic_taint, import_dynamic_taint_for_implementation
from .implementation_registry import sync_all_sources

__all__ = [
    "KnowledgeBase",
    "convert_codeql_file",
    "import_all_dynamic_taint",
    "import_codeql_for_implementation",
    "import_dynamic_taint_for_implementation",
    "sync_all_sources",
]
