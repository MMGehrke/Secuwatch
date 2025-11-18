#!/usr/bin/env python3
"""
SecuWatch-Junior: An Instructional Security Linter

This tool teaches security concepts by scanning Python code.
It uses Python's built-in 'ast' (Abstract Syntax Tree) module
to find common, junior-level security mistakes.

It is designed to be simple, self-contained, and educational,
with no external dependencies besides 'click' for the CLI.
"""

import ast
import click
import os
import logging
from typing import List

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# --- The "Finding" Data Structure ---

class SecurityFinding:
    """
    A simple class to store a single security finding.
    This is simpler than the full "SecurityEvent" from v4.
    """
    def __init__(self, file_path: str, line: int, code: str, issue_type: str, explanation: str, remediation: str):
        self.file_path = file_path
        self.line = line
        self.code = code.strip()
        self.issue_type = issue_type
        self.explanation = explanation
        self.remediation = remediation

    def print_finding(self):
        """Prints the finding in a clear, instructional format."""
        click.secho("\n" + "="*80, fg="yellow")
        click.secho(f"SECURITY ISSUE: {self.issue_type}", fg="red", bold=True)
        click.secho(f"File:           {self.file_path}", fg="cyan")
        click.secho(f"Line:           {self.line}", fg="cyan")
        click.secho(f"Suspicious Code: {self.code}", fg="white")
        click.secho(f"\n[WHAT IT IS]", fg="green", bold=True)
        click.secho(self.explanation)
        click.secho(f"\n[HOW TO FIX IT]", fg="green", bold=True)
        click.secho(self.remediation)
        click.secho("="*80, fg="yellow")

# --- The "Scanners" (AST Visitors) ---

class BaseSecurityVisitor(ast.NodeVisitor):
    """
    This is the base class for all our scanners.
    It inherits from 'NodeVisitor', which provides the magic
    that lets us "visit" different parts of the Python code tree.
    """
    def __init__(self, file_path: str, file_lines: List[str]):
        self.findings: List[SecurityFinding] = []
        self.file_path = file_path
        self.file_lines = file_lines

    def get_line_code(self, node: ast.AST) -> str:
        """Helper function to get the actual line of code from the file."""
        return self.file_lines[node.lineno - 1]

class HardcodedSecretVisitor(BaseSecurityVisitor):
    """
    This visitor finds variables that look like hardcoded secrets.
    It teaches the "Keep Secrets Out of Code" principle.
    """
    # A simple list of variable names that are often secrets.
    SECRET_KEYWORDS = ['PASSWORD', 'API_KEY', 'SECRET_KEY', 'TOKEN']

    def visit_Assign(self, node: ast.Assign):
        """
        This method is automatically called every time the AST
        finds a variable assignment (e.g., x = 10).
        """
        # We only care about simple assignments (e.g., x = "value")
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            var_name = node.targets[0].id.upper()
            
            # Check if the variable name is in our suspicious list
            if any(keyword in var_name for keyword in self.SECRET_KEYWORDS):
                # Check if the value being assigned is a simple string
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    
                    # We found one! Create a finding.
                    finding = SecurityFinding(
                        file_path=self.file_path,
                        line=node.lineno,
                        code=self.get_line_code(node),
                        issue_type="Hardcoded Secret",
                        explanation=(
                            "This code appears to be storing a password or API key directly "
                            "as a string. If you commit this to Git, the secret will be "
                            "visible to anyone who can read the code."
                        ),
                        remediation=(
                            "Never write secrets in your code. Load them from Environment "
                            "Variables. Use `import os` and then `api_key = os.environ.get('MY_API_KEY')`."
                        )
                    )
                    self.findings.append(finding)
        
        # Continue visiting other nodes inside this one
        self.generic_visit(node)

class CommandInjectionVisitor(BaseSecurityVisitor):
    """
    This visitor finds insecure uses of 'subprocess.run' and 'os.system'.
    It teaches about Command Injection vulnerabilities.
    """
    
    def visit_Call(self, node: ast.Call):
        """
        This method is automatically called for every function call
        (e.g., my_function(1, 2) or os.system("ping ...")).
        """
        
        # Check for 'os.system()'
        if (isinstance(node.func, ast.Attribute) and 
            isinstance(node.func.value, ast.Name) and 
            node.func.value.id == 'os' and node.func.attr == 'system'):
            
            finding = SecurityFinding(
                file_path=self.file_path,
                line=node.lineno,
                code=self.get_line_code(node),
                issue_type="Command Injection Risk (os.system)",
                explanation=(
                    "Using `os.system()` is dangerous because it passes the command "
                    "to the system's shell. If a variable is part of that command, "
                    "an attacker could inject malicious commands (e.g., `; rm -rf /`)."
                ),
                remediation=(
                    "Use the `subprocess` module instead. For safe execution, pass commands "
                    "as a list, like `subprocess.run(['ls', '-l', user_folder])`."
                )
            )
            self.findings.append(finding)
        
        # Check for 'subprocess.run(shell=True)'
        if (isinstance(node.func, ast.Attribute) and 
            isinstance(node.func.value, ast.Name) and 
            node.func.value.id == 'subprocess' and node.func.attr == 'run'):
            
            # Check the keyword arguments for 'shell=True'
            for kw in node.keywords:
                if (kw.arg == 'shell' and 
                    isinstance(kw.value, ast.Constant) and kw.value.value is True):
                    
                    finding = SecurityFinding(
                        file_path=self.file_path,
                        line=node.lineno,
                        code=self.get_line_code(node),
                        issue_type="Command Injection Risk (shell=True)",
                        explanation=(
                            "Using `subprocess.run(shell=True)` is dangerous for the same "
                            "reason as `os.system()`. It tells Python to use the system shell, "
                            "which can be tricked by maliciously crafted input."
                        ),
                        remediation=(
                            "Remove `shell=True` and pass your command as a list of arguments. "
                            "For example: `subprocess.run(['echo', user_input])`."
                        )
                    )
                    self.findings.append(finding)
        
        self.generic_visit(node)

# --- The Main Scanner Engine ---

def run_scans(file_path: str) -> List[SecurityFinding]:
    """
    The engine that runs all our visitors on a single file.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            file_lines = content.splitlines()
    except Exception as e:
        logger.error(f"Could not read file {file_path}: {e}")
        return []
    
    try:
        # 1. Parse the code from text into an Abstract Syntax Tree (AST)
        tree = ast.parse(content, filename=file_path)
    except SyntaxError as e:
        logger.error(f"Could not parse Python file {file_path}: {e}")
        return []
    
    all_findings = []
    
    # 2. Create instances of our scanners
    visitors = [
        HardcodedSecretVisitor(file_path, file_lines),
        CommandInjectionVisitor(file_path, file_lines),
        # You can add new scanners here!
    ]
    
    # 3. "Visit" the tree with each scanner
    for visitor in visitors:
        visitor.visit(tree)
        all_findings.extend(visitor.findings)
        
    return all_findings

# --- The Command Line Interface (CLI) ---

@click.command()
@click.argument('path_to_scan', 
                type=click.Path(exists=True, file_okay=True, dir_okay=True, readable=True),
                default='.')
def scan(path_to_scan: str):
    """
    SecuWatch-Junior: An instructional security linter.
    Scans a Python file or directory for common security mistakes
    and explains how to fix them.
    
    If you provide a directory, it will scan all .py files inside it.
    """
    click.secho(f"Scanning: {path_to_scan}", fg="green", bold=True)
    
    total_findings = 0
    
    if os.path.isfile(path_to_scan) and path_to_scan.endswith('.py'):
        findings = run_scans(path_to_scan)
        for finding in findings:
            finding.print_finding()
        total_findings = len(findings)
        
    elif os.path.isdir(path_to_scan):
        # Walk through all files and subdirectories
        for root, _, files in os.walk(path_to_scan):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    findings = run_scans(file_path)
                    for finding in findings:
                        finding.print_finding()
                    total_findings += len(findings)
    else:
        click.secho(f"Error: Path must be a .py file or a directory.", fg="red")
        return
    
    # --- Final Summary ---
    if total_findings == 0:
        click.secho(f"\nScan Complete! No security issues found.", fg="green", bold=True)
    else:
        click.secho(f"\nScan Complete. Found {total_findings} total issues.", fg="yellow", bold=True)

if __name__ == '__main__':
    scan()

