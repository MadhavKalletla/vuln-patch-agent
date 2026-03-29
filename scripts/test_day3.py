# scripts/test_day3.py

from pathlib import Path
from agents.static_analysis.ast_parser import parse_file, get_imports
from agents.static_analysis.cwe_heuristics import (
    find_cwe89_sql_injection,
    find_cwe22_path_traversal,
)

FIXTURE = "tests/fixtures/vulnerable_app.py"


def main():
    # Check if file exists
    if not Path(FIXTURE).exists():
        print(f"❌ File not found: {FIXTURE}")
        return

    # Read source
    source = Path(FIXTURE).read_text(encoding="utf-8").splitlines()

    # Parse AST
    tree = parse_file(FIXTURE)
    if tree is None:
        print("❌ Failed to parse file (syntax error)")
        return

    # Imports
    imports = get_imports(tree)
    print("📦 Imports detected:", imports)

    # Run heuristics
    sql_hits = find_cwe89_sql_injection(tree, FIXTURE, source)
    path_hits = find_cwe22_path_traversal(tree, FIXTURE, source)

    # --- SQL Injection ---
    print(f"\n🚨 SQL Injection (CWE-89): {len(sql_hits)} finding(s)")
    for h in sql_hits:
        print(f"\n Line {h.line_number}: {h.function_name}")
        print(f" Reason: {h.suspicion_reason}")
        print(" Context:")
        for line in h.context_lines:
            print(f"   {line}")

    # --- Path Traversal ---
    print(f"\n🚨 Path Traversal (CWE-22): {len(path_hits)} finding(s)")
    for h in path_hits:
        print(f"\n Line {h.line_number}: {h.function_name}")
        print(f" Reason: {h.suspicion_reason}")
        print(" Context:")
        for line in h.context_lines:
            print(f"   {line}")


if __name__ == "__main__":
    main()