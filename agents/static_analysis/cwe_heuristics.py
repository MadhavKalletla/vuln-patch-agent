# agents/static_analysis/cwe_heuristics.py

import ast
from typing import List
from agents.static_analysis.ast_parser import (
    CallSite,
    get_call_name,
    get_context_lines,
)


# -------------------------------
# CWE-89: SQL Injection
# -------------------------------
def find_cwe89_sql_injection(
    tree: ast.AST,
    file_path: str,
    source_lines: List[str],
) -> List[CallSite]:

    DB_METHODS = {"execute", "executemany", "query", "raw", "filter"}
    hits = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not isinstance(node.func, ast.Attribute):
            continue

        method = node.func.attr

        if method not in DB_METHODS:
            continue

        for arg in node.args:
            # Detect string concat (+) or f-string
            if isinstance(arg, (ast.BinOp, ast.JoinedStr)):
                hits.append(
                    CallSite(
                        file_path=file_path,
                        line_number=node.lineno,
                        col_offset=node.col_offset,
                        function_name=get_call_name(node),
                        context_lines=get_context_lines(
                            source_lines, node.lineno
                        ),
                        is_suspicious=True,
                        suspicion_reason="String concat inside DB call (CWE-89 SQL Injection)",
                    )
                )

    return hits


# -------------------------------
# CWE-22: Path Traversal
# -------------------------------
def find_cwe22_path_traversal(
    tree: ast.AST,
    file_path: str,
    source_lines: List[str],
) -> List[CallSite]:

    PATH_FUNCS = {"open", "join"}
    hits = []

    # ✅ Detect sanitization (abspath + startswith present anywhere)
    has_sanitization = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"abspath", "startswith"}
        for node in ast.walk(tree)
    )

    # ✅ Main detection logic
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Get function name
        fname = ""
        if isinstance(node.func, ast.Attribute):
            fname = node.func.attr
        elif isinstance(node.func, ast.Name):
            fname = node.func.id

        if fname not in PATH_FUNCS:
            continue

        for arg in node.args:
            # ✅ Flag only unsafe variable usage AND no sanitization
            if (
                isinstance(arg, ast.Name)
                and arg.id not in {"BASE_DIR", "safe_path"}
                and not has_sanitization
            ):
                hits.append(
                    CallSite(
                        file_path=file_path,
                        line_number=node.lineno,
                        col_offset=node.col_offset,
                        function_name=fname,
                        context_lines=get_context_lines(
                            source_lines, node.lineno
                        ),
                        is_suspicious=True,
                        suspicion_reason="Variable path arg — possible traversal (CWE-22)",
                    )
                )

    # ✅ Remove duplicates
    seen = set()
    unique_hits = []

    for h in hits:
        key = (h.line_number, h.function_name)
        if key not in seen:
            seen.add(key)
            unique_hits.append(h)

    return unique_hits

# -------------------------------
# CWE-400: ReDoS
# -------------------------------
def find_cwe400_redos(
    tree: ast.AST,
    file_path: str,
    source_lines: List[str],
) -> List[CallSite]:

    RE_METHODS = {"match", "search", "compile", "fullmatch", "findall"}
    hits = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if not (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in RE_METHODS
        ):
            continue

        if node.args and not isinstance(node.args[0], ast.Constant):
            hits.append(
                CallSite(
                    file_path=file_path,
                    line_number=node.lineno,
                    col_offset=node.col_offset,
                    function_name=f"re.{node.func.attr}",
                    context_lines=get_context_lines(
                        source_lines, node.lineno
                    ),
                    is_suspicious=True,
                    suspicion_reason="Dynamic regex pattern — potential ReDoS (CWE-400)",
                )
            )

    return hits


# -------------------------------
# Registry
# -------------------------------
CWE_HEURISTICS = {
    "CWE-89": find_cwe89_sql_injection,
    "CWE-22": find_cwe22_path_traversal,
    "CWE-400": find_cwe400_redos,
}