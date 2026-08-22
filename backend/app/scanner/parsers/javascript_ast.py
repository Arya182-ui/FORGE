import esprima
from pathlib import Path
from typing import Tuple, Optional, Dict, Any


class JavaScriptParseError(Exception):
    pass


class JavaScriptASTParser:
    @staticmethod
    def parse_file(file_path: Path) -> Tuple[Optional[Any], str, int, Optional[str]]:
        """
        Safely parses a JavaScript/TypeScript source file into an Esprima AST tree.
        Returns (ast_tree, source_code, line_count, error_message).
        NEVER executes user code.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()

            line_count = len(source_code.splitlines())

            try:
                # Tolerant parsing to handle common modern syntax extensions
                tree = esprima.parseModule(source_code, {"loc": True, "range": True, "tolerant": True})
                return tree, source_code, line_count, None
            except Exception:
                try:
                    tree = esprima.parseScript(source_code, {"loc": True, "range": True, "tolerant": True})
                    return tree, source_code, line_count, None
                except Exception as se:
                    err_msg = f"JavaScript parse error in {file_path.name}: {str(se)}"
                    return None, source_code, line_count, err_msg

        except Exception as io_err:
            return None, "", 0, f"Failed to read JavaScript file {file_path.name}: {str(io_err)}"
