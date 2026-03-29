# agents/static_analysis/ast_parser.py

import ast
from dataclasses import dataclass, field
from typing import Optional, List
from pathlib import Path


@dataclass
class CallSite:
    file_path: str
    line_number: int
    col_offset: int
    function_name: str
    context_lines: List[str] = field(default_factory=list)
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None


def parse_file(file_path: str) -> Optional[ast.Module]:
    """Parse a Python source file into an AST. Returns None on syntax error."""
    try:
        source = Path(file_path).read_text(
            encoding="utf-8",
            errors="replace"
        )
        return ast.parse(source, filename=file_path)
    except SyntaxError:
        return None


def get_imports(tree: ast.Module) -> List[str]:
    """Return all top-level package names imported in this module."""
    imports = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])

        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])

    return list(imports)


def get_context_lines(
    source_lines: List[str],
    lineno: int,
    window: int = 3
) -> List[str]:
    """Return surrounding lines for context."""
    start = max(0, lineno - window - 1)
    end = min(len(source_lines), lineno + window)

    return [
        f"{start + i + 1}: {source_lines[start + i]}"
        for i in range(end - start)
    ]


def get_call_name(node: ast.Call) -> str:
    """Extract a readable function name from a Call node."""
    if isinstance(node.func, ast.Attribute):
        if isinstance(node.func.value, ast.Name):
            owner = node.func.value.id
        else:
            owner = "object"
        return f"{owner}.{node.func.attr}"

    elif isinstance(node.func, ast.Name):
        return node.func.id

    return "(unknown)"