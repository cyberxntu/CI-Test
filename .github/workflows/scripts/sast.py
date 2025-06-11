import ast
import os
import sys
import json

detected_issues = []

class SASTScanner(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename

    def report(self, node, issue_type, desc):
        detected_issues.append({
            "file": self.filename,
            "line": node.lineno,
            "type": issue_type,
            "desc": desc
        })

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id == 'secret_key':
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    self.report(node, "Hardcoded Secret", "Hardcoded secret_key found")
        self.generic_visit(node)

    def visit_Call(self, node):
        if isinstance(node.func, ast.Attribute) and node.func.attr == 'execute':
            for arg in node.args:
                if isinstance(arg, ast.Constant):
                    if 'INSERT INTO users' in arg.value and 'password' in arg.value:
                        self.report(node, "Plaintext Password Storage", "Possible storage of plaintext password in DB")

        if isinstance(node.func, ast.Name) and node.func.id == 'render_template':
            for kw in node.keywords:
                if isinstance(kw.value, ast.Name):
                    self.report(node, "Potential XSS", f"Rendering variable '{kw.arg}' without sanitization")

        if isinstance(node.func, ast.Attribute):
            if node.func.attr == 'system' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os':
                self.report(node, "Command Injection", "Use of os.system may lead to command injection")
            if node.func.attr == 'run' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'subprocess':
                self.report(node, "Command Injection", "Use of subprocess.run may lead to command injection")

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        if any(isinstance(d, ast.Call) and hasattr(d.func, 'attr') and d.func.attr == 'route' for d in node.decorator_list):
            if any("POST" in ast.dump(d) for d in node.decorator_list):
                if 'csrf' not in node.name.lower():
                    self.report(node, "Missing CSRF Protection", f"Function '{node.name}' handles POST without CSRF")

        for n in ast.walk(node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                if n.func.id in ['eval', 'exec']:
                    self.report(n, "Insecure Function", f"Use of {n.func.id} is dangerous and can lead to code execution")

        self.generic_visit(node)

    def visit_If(self, node):
        src = ast.unparse(node) if hasattr(ast, 'unparse') else ""
        if 'admin' in src and 'username' in src and 'session' in src:
            if 'admin' not in src or '==' not in src:
                self.report(node, "Broken Access Control", "Admin route lacks strict session verification")
        self.generic_visit(node)

def load_ignore_list(file_path=".scannerignore"):
    ignore_list = set()
    if os.path.exists(file_path):
        with open(file_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ignore_list.add(line)
    return ignore_list

def should_ignore(filepath, ignore_list):
    return any(ignored in filepath for ignored in ignore_list)

def analyze_file(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            tree = ast.parse(f.read(), filename=filepath)
            scanner = SASTScanner(filepath)
            scanner.visit(tree)
    except Exception as e:
        print(f"[!] Failed to parse {filepath}: {e}")

if __name__ == '__main__':
    ignore_list = load_ignore_list()
    targets = sys.argv[1:] if len(sys.argv) > 1 else ["."]

    for target in targets:
        if os.path.isfile(target) and target.endswith(".py"):
            if not should_ignore(target, ignore_list):
                analyze_file(target)
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                for file in files:
                    if file.endswith(".py"):
                        filepath = os.path.join(root, file)
                        if not should_ignore(filepath, ignore_list):
                            analyze_file(filepath)

    if detected_issues:
        with open("sast_results.json", "w") as f:
            json.dump(detected_issues, f, indent=2)
        print("SAST issues found:")
        for issue in detected_issues:
            print(issue)
        sys.exit(1)
    else:
        print("No SAST issues found.")
        sys.exit(0)
