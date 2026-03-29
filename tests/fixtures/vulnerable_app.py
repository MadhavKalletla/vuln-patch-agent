import os

BASE_DIR = '/data/reports'

def read_report(filename):
    safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))

    if not safe_path.startswith(os.path.abspath(BASE_DIR)):
        raise ValueError("Invalid file path")

    with open(safe_path) as f:
        return f.read()