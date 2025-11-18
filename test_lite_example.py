#!/usr/bin/env python3
"""Test file for secuwatch_lite - contains intentional security issues for testing"""

# This should trigger HardcodedSecretVisitor
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
PASSWORD = "my_secret_password_123"

# This should trigger CommandInjectionVisitor
import os
import subprocess

def unsafe_function():
    user_input = "some_user_input"
    # Dangerous: os.system with user input
    os.system(f"echo {user_input}")
    
    # Dangerous: subprocess.run with shell=True
    subprocess.run(f"ls -l {user_input}", shell=True)

