# SecuWatch - Security Monitoring Tool Evolution

## Overview

SecuWatch is a family of command-line security monitoring tools that provides **real-time security monitoring** for AI-assisted development, enforcing strict compliance with **MCP 2025-06-18 Security Best Practices** using an **80/20 rule** and **MITRE DEFEND** mapping.

The SecuWatch family includes:
- **SecuWatch-Lite**: Educational tool for learning security concepts (minimal dependencies)
- **SecuWatch v2-v4**: Production-ready security monitoring with increasing levels of enterprise features

## 📋 Version History

### **SecuWatch-Lite** (SecuWatch-Junior) - Educational & Instructional
- **File**: `secuwatch_lite.py`
- **Key Features**: 
  - **Educational Focus**: Designed to teach security concepts to junior developers
  - **Zero External Dependencies**: Only requires `click` for CLI (uses built-in `ast` module)
  - **Simple & Self-Contained**: Easy to understand and modify
  - **Instructional Output**: Each finding includes explanations and remediation guidance
  - **Common Security Mistakes**: Detects hardcoded secrets and command injection risks
- **Dependencies**: `click>=8.1.0` (only external dependency)
- **Use Case**: Learning environments, educational projects, beginners learning security best practices

### **SecuWatch v4** (Latest) - Enterprise Ready
- **File**: `secuwatch_v4.py`
- **Key Features**: 
  - **YAML Configuration Management**: Fully configurable rulesets, thresholds, and behavior
  - **Debounced File Monitoring**: Prevents rapid-fire scans during active development
  - **Asynchronous Processing**: Non-blocking scans for better developer experience
  - **Robust Error Handling**: Graceful degradation with detailed error logging and retry logic
  - **False Positive Management**: Inline ignore comments with justification tracking
  - **Enhanced Testability**: Decoupled core logic for comprehensive unit testing
  - **IDE Integration Ready**: Structured JSON output for external tool integration
- **Dependencies**: `semgrep>=1.45.0`, `pip-audit>=2.6.0`, `click>=8.1.0`, `watchdog>=3.0.0`, `pyyaml>=6.0`
- **Use Case**: Enterprise environments, production systems, teams requiring configuration flexibility

### **SecuWatch v3** - IDE Integration Ready
- **File**: `secuwatch_v3.py`
- **Key Features**: IDE integration ready, Semgrep SAST with taint analysis, structured JSON output
- **Dependencies**: `semgrep>=1.45.0` (replaces bandit), `pip-audit>=2.6.0`, `click>=8.1.0`, `watchdog>=3.0.0`
- **Use Case**: Production environments, IDE extensions, external tool integration

### **SecuWatch v2** - High-Performance Security Monitoring
- **File**: `secuwatch.py`
- **Key Features**: Cached dependency scans, entropy-based secret detection, context-aware detection
- **Dependencies**: `bandit>=1.7.0`, `pip-audit>=2.6.0`, `click>=8.1.0`, `watchdog>=3.0.0`
- **Use Case**: Development environments, CI/CD pipelines

## 🚀 Quick Start

### Installation

#### **SecuWatch-Lite** (Educational - Minimal Dependencies)
```bash
# Install only click (the only external dependency)
pip install click>=8.1.0
```

#### **SecuWatch v4** (Recommended for Enterprise)
```bash
# Install v4 dependencies with enterprise features
pip install -r requirements_v4.txt
```

#### **SecuWatch v3**
```bash
# Install v3 dependencies (Semgrep SAST)
pip install -r requirements_v3.txt
```

#### **SecuWatch v2**
```bash
# Install v2 dependencies (Bandit SAST)
pip install -r requirements_v2.txt
```

### Usage by Version

#### **SecuWatch-Lite** (Educational)
```bash
# Scan a single Python file
python secuwatch_lite.py path/to/file.py

# Scan a directory (recursively scans all .py files)
python secuwatch_lite.py /path/to/your/project

# Scan current directory (default)
python secuwatch_lite.py
```

#### **SecuWatch v4** (Enterprise Ready)
```bash
# Monitor with default configuration
python secuwatch_v4.py watch /path/to/your/project

# Monitor with custom configuration file
python secuwatch_v4.py watch /path/to/your/project --config .secuwatch.yaml

# One-time security scan
python secuwatch_v4.py scan --config .secuwatch.yaml

# Enable verbose logging
python secuwatch_v4.py watch /path/to/your/project --verbose
```

#### **SecuWatch v3**
```bash
# Monitor a directory for security violations with Semgrep SAST
python secuwatch_v3.py watch /path/to/your/project
```

#### **SecuWatch v2**
```bash
# Monitor a directory for security violations with Bandit SAST
python secuwatch.py watch /path/to/your/project
```

## 🎯 Features Comparison

| Feature | Lite | v2 | v3 | v4 |
|---------|------|----|----|----|
| **Educational Focus** | ✅ Instructional | ❌ | ❌ | ❌ |
| **Dependencies** | Minimal (click only) | Medium | Medium | Full |
| **Real-Time Monitoring** | ❌ | ✅ | ✅ | ✅ |
| **SAST Engine** | Built-in AST | Bandit | Semgrep with Taint Analysis | Configurable Semgrep |
| **Secret Detection** | Pattern-based | Entropy-based | Entropy-based | Configurable Entropy |
| **Command Injection Detection** | ✅ AST-based | ❌ | ✅ (via Semgrep) | ✅ (via Semgrep) |
| **Hardcoded Secrets** | ✅ Pattern matching | ✅ Entropy | ✅ Entropy | ✅ Configurable Entropy |
| **Dependency Scanning** | ❌ | ✅ Cached pip-audit | ✅ Cached pip-audit | ✅ Cached pip-audit + Retry |
| **IDE Integration** | ❌ | ❌ | ✅ Structured JSON | ✅ Enhanced JSON + SARIF |
| **Taint Analysis** | ❌ | ❌ | ✅ SQLi, Command Injection, XSS | ✅ Enhanced Taint Analysis |
| **Configuration Management** | ❌ | ❌ | ❌ | ✅ YAML Configuration |
| **Debounced Monitoring** | ❌ | ❌ | ❌ | ✅ Threading-based Debouncing |
| **Error Handling** | Basic | Basic | Basic | ✅ Robust with Retry Logic |
| **False Positive Suppression** | ❌ | ❌ | ❌ | ✅ Inline Ignore Comments |
| **Output Formats** | Console (instructional) | Console only | Console + JSON | Console + JSON + SARIF |
| **Unit Testing** | ❌ | ❌ | ❌ | ✅ Comprehensive Test Suite |
| **Performance** | Fast (simple scans) | High (cached) | High (cached) | ✅ Optimized (debounced + async) |

## 🛡️ Security Policies (All Versions)

### **Sensitive Systems Detection**
- **Authentication Systems**: Detects functions/modules handling login, JWT, OAuth, sessions
- **Payment Processing**: Detects Stripe, PayPal, billing, transaction handling
- **Sensitive Data Handling**: Detects encryption, hashing, PII, credentials
- **Access Control**: Detects RBAC, permissions, authorization logic
- **Action**: Displays highly visible warning requiring human security expert review

### **Policy A: Dependency Integrity (DTE0019)**
- **Rule**: Scan `requirements.txt` for high-severity CVEs
- **Enhancement**: Hash-based caching prevents redundant network scans
- **Action**: Uses `pip-audit` to detect vulnerabilities (only when file changes)
- **On Violation**: Halt monitoring and alert with CRITICAL severity

### **Policy B: Static Code Analysis (DTE0010)**

#### **v2 Implementation**
- **SAST Engine**: `bandit` for robust AST-based analysis
- **Secret Detection**: Shannon entropy-based (entropy threshold: 4.5)
- **Detection**: High-entropy strings (20-100 chars)

#### **v3 Implementation**
- **SAST Engine**: `semgrep` with taint analysis capabilities
- **Secret Detection**: Shannon entropy-based (entropy threshold: 4.5)
- **Enhanced Detection**: SQLi, Command Injection, XSS via taint tracking
- **Rulesets**: `p/default` and `p/trailofbits` for comprehensive coverage

### **Policy C: Input Validation & Tool Safety (DTE0001)**
- **Rule**: MCP Tool endpoints must have Pydantic validation
- **Rule**: No unsafe global operations without explicit scope
- **Action**: AST-based function analysis
- **On Violation**: Warning for missing validation

### **Policy D: Output Integrity (Output Safety)**
- **Rule**: MCP Tool endpoints must return structured data
- **Rule**: Return types must be annotated (Dict or pydantic.BaseModel)
- **Action**: AST-based return type checking
- **On Violation**: Warning for unstructured outputs

### **Policy E: Context-Aware Sensitive System Detection**
- **Rule**: Detects anomalous placement of sensitive logic in non-sensitive files
- **Enhancement**: Baseline tracking learns expected locations for sensitive code
- **Systems Tracked**: Authentication, Payment, Encryption, Access Control
- **Action**: AST-based pattern detection with context awareness
- **On Violation**: CRITICAL alert for anomalous placement

### **Policy F: Sensitive Data Logging Check (v3 Only)**
- **Rule**: Detects sensitive data in logging statements
- **Patterns**: password, secret, token, key, api_key, private_key, credential, auth, session, cookie
- **Action**: AST-based logging call analysis
- **On Violation**: Warning for potential data exposure

## 🚨 Human Review Flagging (20% Rule)

When a Python file contains the exact flag:
```python
# 🚨 20_PERCENT_RISK_AUDIT
```

SecuWatch will:
- Display a **highly visible alert**
- Exclude the file from automated checks (exits scan early)
- Instruct developer to pause automation
- Require human security expert review

## 🔧 IDE Integration (v3 Only)

### External API Usage
```python
from secuwatch_v3 import SecurityPolicyEngine

# Initialize the engine
engine = SecurityPolicyEngine()

# Scan a file and get structured results
events = engine.scan_file("path/to/file.py")

# Convert to JSON for external tools
json_events = [event.to_dict() for event in events]
```

### VS Code Extension Integration
The v3 engine can be integrated into VS Code Language Server Extensions:
- Returns structured `SecurityEvent` objects
- No direct console output (separation of concerns)
- JSON serialization support via `to_dict()` method

## 📊 MITRE DEFEND Mapping

| Policy | MITRE ID | Description | v2 | v3 |
|--------|----------|-------------|----|----|
| A | DTE0019 | Software Supply Chain Integrity (Cached) | ✅ | ✅ |
| B | DTE0010 | Code Scanning (SAST + Entropy) | ✅ Bandit | ✅ Semgrep |
| C | DTE0001 | Data Validation | ✅ | ✅ |
| D | DTE_OUTPUT_SAFETY | Output Safety | ✅ | ✅ |
| E | DTE_SENSITIVE_SYSTEM | Context-Aware Sensitive Systems | ✅ | ✅ |
| F | DTE_LOGGING_EXPOSURE | Sensitive Data Logging | ❌ | ✅ |

## 🛡️ Security Compliance

- **MCP 2025-06-18 Security Best Practices**: ✅ Fully Compliant
- **Zero-Trust Architecture**: ✅ Implemented
- **80/20 Rule Enforcement**: ✅ Operational
- **MITRE DEFEND Mapping**: ✅ Complete

## ⚠️ Security Statement

**I have verified the integrity of all chosen dependencies:**

### **SecuWatch-Lite Dependencies**
- `click`: CLI framework, actively maintained
- Built-ins (`ast`): Core functionality module (Python standard library)
- **Note**: SecuWatch-Lite has minimal dependencies by design for educational use

### **v2 Dependencies**
- `watchdog`: File system monitoring, actively maintained, no critical CVEs
- `click`: CLI framework, actively maintained
- `bandit`: Robust AST-based security linter, actively maintained
- `pip-audit`: Official PyPA vulnerability scanner, actively maintained
- Built-ins (`ast`, `subprocess`, `hashlib`, `math`): Core functionality modules

### **v3 Dependencies**
- `watchdog`: File system monitoring, actively maintained, no critical CVEs
- `click`: CLI framework, actively maintained
- `semgrep`: Advanced SAST with taint analysis, actively maintained
- `pip-audit`: Official PyPA vulnerability scanner, actively maintained
- Built-ins (`ast`, `subprocess`, `hashlib`, `math`): Core functionality modules

All dependencies are reputable, actively maintained, and free of known high-severity vulnerabilities.

## 📝 Security Statement Summary

SecuWatch adheres to an 80/20 rule for security automation:
- **80% Automated**: Critical security checks automatically enforced
- **20% Human Review**: Complex business logic flagged for expert review
- **Performance Caching**: Hash-based dependency scan caching
- **Low-Noise Detection**: Entropy-based secrets, context-aware sensitive systems
- **Secure Libraries**: Uses watchdog, click, semgrep/bandit, pip-audit, and built-in modules
- **MITRE Mapping**: DTE0019, DTE0010, DTE0001, DTE_OUTPUT_SAFETY, DTE_SENSITIVE_SYSTEM compliance validated

## 🆕 Version Evolution

### **What's New in SecuWatch-Lite (Educational)**
- **Educational Focus**: Designed specifically to teach security concepts to junior developers
- **Minimal Dependencies**: Only requires `click` - uses Python's built-in `ast` module for analysis
- **Instructional Output**: Each finding includes clear explanations of what the issue is and how to fix it
- **Common Security Mistakes**: Focuses on the most common beginner mistakes:
  - Hardcoded secrets (passwords, API keys, tokens)
  - Command injection risks (`os.system()`, `subprocess.run(shell=True)`)
- **Easy to Extend**: Simple, well-documented code structure makes it easy to add new scanners
- **Self-Contained**: No external security tools required - perfect for learning environments

### **What's New in v3**
- **IDE Integration**: Structured output for external tool integration
- **Advanced SAST**: Semgrep with taint analysis for complex vulnerabilities
- **Enhanced Detection**: SQLi, Command Injection, XSS detection
- **Logging Security**: New policy for sensitive data in logs
- **API Ready**: Core engine can be called externally

### **What's New in v2**
- **Performance Improvements**: Cached dependency scans using MD5 hashing
- **Better Secret Detection**: Shannon entropy-based high-signal detection (threshold 4.5)
- **Context-Aware Security**: Baseline tracking for sensitive files reduces false positives
- **Integrated SAST**: Uses `bandit` for robust AST-based static analysis
- **Reduced Developer Friction**: Only scans requirements.txt when it changes

## 🔄 Migration Guide

### **From v2 to v3**
1. Update dependencies: `pip install -r requirements_v3.txt` (replaces bandit with semgrep)
2. Use `secuwatch_v3.py` instead of `secuwatch.py`
3. Same CLI interface: `python secuwatch_v3.py watch /path`
4. Enhanced SAST detection with taint analysis
5. New logging exposure checks

### **Choosing Your Version**
- **Use SecuWatch-Lite** for: Learning environments, educational projects, teaching security concepts, beginners
- **Use v4** for: Enterprise environments, production systems, teams requiring configuration flexibility, CI/CD with SARIF support
- **Use v3** for: Development environments, IDE extensions, external integrations, Semgrep SAST requirements
- **Use v2** for: Legacy compatibility, simple monitoring needs, Bandit SAST preference, minimal dependencies
