#!/usr/bin/env python3
"""
SecuWatch v4 Unit Tests
Test suite for enterprise-grade security monitoring tool
"""

import pytest
import tempfile
import os
import sys
from pathlib import Path

# Add the parent directory to the path to import secuwatch_v4
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from secuwatch_v4 import (
    _shannon_entropy,
    IgnoreCommentParser,
    ConfigManager,
    SecuWatchConfig,
    SecurityEvent,
    SecurityPolicyEngine
)


class TestEntropyCalculation:
    """Test cases for Shannon entropy calculation"""
    
    def test_empty_string_entropy(self):
        """Test entropy calculation for empty string"""
        assert _shannon_entropy("") == 0.0
    
    def test_single_character_entropy(self):
        """Test entropy calculation for single character"""
        assert _shannon_entropy("a") == 0.0
    
    def test_repeated_characters_low_entropy(self):
        """Test entropy calculation for repeated characters (low entropy)"""
        entropy = _shannon_entropy("aaaaa")
        assert entropy < 1.0  # Low entropy for repeated characters
    
    def test_random_string_high_entropy(self):
        """Test entropy calculation for random-looking string (high entropy)"""
        entropy = _shannon_entropy("aB3dE7gH9jK2mN5pQ8sT1vW4xY6zA")
        assert entropy > 4.0  # High entropy for random-looking string
    
    def test_known_entropy_values(self):
        """Test entropy calculation with known values"""
        # Test with binary string
        entropy = _shannon_entropy("01010101")
        assert entropy == 1.0  # Perfect binary entropy
        
        # Test with uniform distribution
        entropy = _shannon_entropy("abcdefgh")
        assert entropy == 3.0  # log2(8) = 3


class TestIgnoreCommentParser:
    """Test cases for inline ignore comment parsing"""
    
    def test_secuwatch_ignore_with_reason(self):
        """Test parsing secuwatch ignore comment with reason"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('password = "secret123"\n')
            f.write('# secuwatch: ignore HIGH_ENTROPY_SECRET reason="Test password for development"\n')
            f.write('api_key = "sk-1234567890abcdef"\n')
            temp_file = f.name
        
        try:
            ignore_rules = IgnoreCommentParser.parse_ignore_comments(temp_file, 3)
            assert len(ignore_rules) == 1
            assert ignore_rules[0][0] == "HIGH_ENTROPY_SECRET"
            assert "Test password for development" in ignore_rules[0][1]
        finally:
            os.unlink(temp_file)
    
    def test_noqa_ignore(self):
        """Test parsing noqa ignore comment"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('# noqa: SECUW001\n')
            f.write('unsafe_code = eval(user_input)\n')
            temp_file = f.name
        
        try:
            ignore_rules = IgnoreCommentParser.parse_ignore_comments(temp_file, 2)
            assert len(ignore_rules) == 1
            assert ignore_rules[0][0] == "SECUW001"
        finally:
            os.unlink(temp_file)
    
    def test_multiple_ignore_comments(self):
        """Test parsing multiple ignore comments"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('# secuwatch: ignore HIGH_ENTROPY_SECRET reason="Test data"\n')
            f.write('# noqa: MISSING_VALIDATION\n')
            f.write('test_code = "value"\n')
            temp_file = f.name
        
        try:
            ignore_rules = IgnoreCommentParser.parse_ignore_comments(temp_file, 3)
            assert len(ignore_rules) == 2
            rule_ids = [rule[0] for rule in ignore_rules]
            assert "HIGH_ENTROPY_SECRET" in rule_ids
            assert "MISSING_VALIDATION" in rule_ids
        finally:
            os.unlink(temp_file)
    
    def test_no_ignore_comments(self):
        """Test parsing file with no ignore comments"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('normal_code = "value"\n')
            f.write('another_line = 123\n')
            temp_file = f.name
        
        try:
            ignore_rules = IgnoreCommentParser.parse_ignore_comments(temp_file, 2)
            assert len(ignore_rules) == 0
        finally:
            os.unlink(temp_file)


class TestConfigManager:
    """Test cases for configuration management"""
    
    def test_default_config_creation(self):
        """Test creation of default configuration"""
        config = SecuWatchConfig()
        
        # Test default values
        assert config.entropy_threshold == 4.5
        assert config.debounce_timer == 500
        assert "p/default" in config.semgrep_rulesets
        assert "p/trailofbits" in config.semgrep_rulesets
        assert config.enable_checks['dependency_integrity'] is True
        assert config.enable_checks['sast_semgrep'] is True
    
    def test_config_file_loading(self):
        """Test loading configuration from YAML file"""
        config_data = {
            'entropy_threshold': 5.0,
            'debounce_timer': 1000,
            'semgrep_rulesets': ['p/security-audit'],
            'enable_checks': {
                'dependency_integrity': False,
                'sast_semgrep': True
            }
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            import yaml
            yaml.dump(config_data, f)
            temp_file = f.name
        
        try:
            config = ConfigManager.load_config(temp_file)
            assert config.entropy_threshold == 5.0
            assert config.debounce_timer == 1000
            assert config.semgrep_rulesets == ['p/security-audit']
            assert config.enable_checks['dependency_integrity'] is False
            assert config.enable_checks['sast_semgrep'] is True
        finally:
            os.unlink(temp_file)
    
    def test_should_ignore_path(self):
        """Test path ignoring logic"""
        config = SecuWatchConfig()
        
        # Test ignored paths
        assert ConfigManager.should_ignore_path("/path/to/__pycache__/file.py", config) is True
        assert ConfigManager.should_ignore_path("/path/to/.git/config", config) is True
        assert ConfigManager.should_ignore_path("/path/to/node_modules/package.json", config) is True
        
        # Test non-ignored paths
        assert ConfigManager.should_ignore_path("/path/to/src/main.py", config) is False
        assert ConfigManager.should_ignore_path("/path/to/tests/test_file.py", config) is False


class TestSecurityEvent:
    """Test cases for SecurityEvent model"""
    
    def test_security_event_creation(self):
        """Test SecurityEvent creation and serialization"""
        event = SecurityEvent(
            event_type="SAST_FAILURE",
            file_path="/path/to/file.py",
            line_num=42,
            mitre_id="DTE0010",
            message="Test security issue",
            severity="CRITICAL",
            rule_id="TEST_RULE"
        )
        
        assert event.event_type == "SAST_FAILURE"
        assert event.file_path == "/path/to/file.py"
        assert event.line_num == 42
        assert event.mitre_id == "DTE0010"
        assert event.severity == "CRITICAL"
        assert event.rule_id == "TEST_RULE"
        assert event.suppressed is False
    
    def test_security_event_to_dict(self):
        """Test SecurityEvent to_dict serialization"""
        event = SecurityEvent(
            event_type="TEST_EVENT",
            file_path="/test/file.py",
            line_num=1,
            mitre_id="DTE_TEST",
            message="Test message",
            severity="WARNING"
        )
        
        event_dict = event.to_dict()
        
        assert isinstance(event_dict, dict)
        assert event_dict['event_type'] == "TEST_EVENT"
        assert event_dict['file_path'] == "/test/file.py"
        assert event_dict['line_num'] == 1
        assert event_dict['mitre_id'] == "DTE_TEST"
        assert event_dict['message'] == "Test message"
        assert event_dict['severity'] == "WARNING"
        assert 'timestamp' in event_dict


class TestSecurityPolicyEngine:
    """Test cases for SecurityPolicyEngine"""
    
    def test_engine_initialization(self):
        """Test SecurityPolicyEngine initialization"""
        config = SecuWatchConfig()
        engine = SecurityPolicyEngine(config)
        
        assert engine.config == config
        assert len(engine.human_review_flagged) == 0
        assert len(engine.security_events) == 0
        assert engine.req_hash is None
        assert len(engine.sensitive_file_baseline) == 0
    
    def test_human_review_flag_detection(self):
        """Test human review flag detection"""
        config = SecuWatchConfig()
        engine = SecurityPolicyEngine(config)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('normal_code = "value"\n')
            f.write('# 🚨 20_PERCENT_RISK_AUDIT\n')
            f.write('complex_business_logic = process_data()\n')
            temp_file = f.name
        
        try:
            has_flag = engine._check_human_review_flag(temp_file)
            assert has_flag is True
        finally:
            os.unlink(temp_file)
    
    def test_no_human_review_flag(self):
        """Test file without human review flag"""
        config = SecuWatchConfig()
        engine = SecurityPolicyEngine(config)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('normal_code = "value"\n')
            f.write('another_line = 123\n')
            temp_file = f.name
        
        try:
            has_flag = engine._check_human_review_flag(temp_file)
            assert has_flag is False
        finally:
            os.unlink(temp_file)


# Integration Tests
class TestIntegration:
    """Integration tests for complete workflows"""
    
    def test_entropy_detection_integration(self):
        """Test complete entropy detection workflow"""
        config = SecuWatchConfig()
        config.entropy_threshold = 4.0  # Lower threshold for testing
        engine = SecurityPolicyEngine(config)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"\n')
            f.write('normal_string = "hello world"\n')
            temp_file = f.name
        
        try:
            events = engine.scan_file(temp_file)
            
            # Should find high-entropy secret
            entropy_events = [e for e in events if e.event_type == "SAST_FAILURE" and e.rule_id == "HIGH_ENTROPY_SECRET"]
            assert len(entropy_events) == 1
            assert entropy_events[0].severity == "CRITICAL"
        finally:
            os.unlink(temp_file)
    
    def test_suppression_logic_integration(self):
        """Test complete suppression logic workflow"""
        config = SecuWatchConfig()
        config.entropy_threshold = 4.0  # Lower threshold for testing
        engine = SecurityPolicyEngine(config)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write('api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"\n')
            f.write('# secuwatch: ignore HIGH_ENTROPY_SECRET reason="Test API key for development"\n')
            f.write('normal_string = "hello world"\n')
            temp_file = f.name
        
        try:
            events = engine.scan_file(temp_file)
            
            # Should find high-entropy secret but suppressed
            entropy_events = [e for e in events if e.event_type == "SAST_FAILURE" and e.rule_id == "HIGH_ENTROPY_SECRET"]
            assert len(entropy_events) == 1
            assert entropy_events[0].suppressed is True
            assert "Suppressed" in entropy_events[0].message
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    # Run tests if executed directly
    pytest.main([__file__, '-v'])
