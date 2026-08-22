import ast
from pathlib import Path
from typing import Tuple, Optional


class PythonParseError(Exception):
    pass


class PythonASTParser:
    @staticmethod
    def parse_file(file_path: Path) -> Tuple[Optional[ast.AST], str, int, Optional[str]]:
        """
        Safely reads file content and parses it into a Python AST tree.
        Returns (ast_tree, source_code, line_count, error_message).
        NEVER executes user code.
        """
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()

            line_count = len(source_code.splitlines())

            try:
                tree = ast.parse(source_code, filename=str(file_path))
                return tree, source_code, line_count, None
            except SyntaxError as se:
                err_msg = f"Syntax error in {file_path.name}:{se.lineno}: {se.msg}"
                return None, source_code, line_count, err_msg
            except Exception as e:
                err_msg = f"Parse failure in {file_path.name}: {str(e)}"
                return None, source_code, line_count, err_msg

        except Exception as io_err:
            return None, "", 0, f"Failed to read file {file_path.name}: {str(io_err)}"
