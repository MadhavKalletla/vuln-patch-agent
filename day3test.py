import ast

source = '''
import sqlite3
def get_user(user_id):
    conn = sqlite3.connect('app.db')
    query = 'SELECT * FROM users WHERE id = ' + user_id
    return conn.execute(query).fetchone()
'''

tree = ast.parse(source)

# Print every node type in the tree
node_types = set(type(n).__name__ for n in ast.walk(tree))
print('Node types:', sorted(node_types))

# Find every function call
print('\nFunction calls:')
# Track variables that use string concatenation
concat_vars = set()

for node in ast.walk(tree):
    if isinstance(node, ast.Assign):
        if isinstance(node.value, ast.BinOp):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    concat_vars.add(target.id)

# Now check execute()
print('\nSuspicious patterns (string concat in DB calls):')
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            for arg in node.args:
                if isinstance(arg, ast.Name) and arg.id in concat_vars:
                    print(f' Line {node.lineno}: SQL injection risk!')