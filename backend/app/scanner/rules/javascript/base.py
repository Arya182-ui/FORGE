from abc import abstractmethod
from typing import List, Any, Callable
from backend.app.scanner.rules.base import BaseRule, FindingData


class BaseJSRule(BaseRule):
    language: str = "javascript"

    def walk_ast(self, node: Any, visitor_fn: Callable[[Any], None]):
        """Recursively walks Esprima AST nodes and applies visitor callback."""
        if node is None:
            return

        visitor_fn(node)

        # Handle object or dict node representations
        if hasattr(node, "__dict__"):
            items = node.__dict__.items()
        elif isinstance(node, dict):
            items = node.items()
        else:
            return

        for key, val in items:
            if key in {"loc", "range"}:
                continue
            if isinstance(val, list):
                for item in val:
                    self.walk_ast(item, visitor_fn)
            elif hasattr(val, "type") or isinstance(val, dict):
                self.walk_ast(val, visitor_fn)

    @abstractmethod
    def analyze_javascript_ast(self, tree: Any, file_path: str, source_code: str) -> List[FindingData]:
        """Analyzes JavaScript AST tree and returns findings."""
        pass
