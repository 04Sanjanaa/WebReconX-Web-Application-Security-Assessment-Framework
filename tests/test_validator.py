import pytest
from webreconx.core.validator import TargetValidator

def test_url_normalization():
    validator = TargetValidator()
    
    # Standard normalization
    assert validator.normalize_url("http://example.com") == "http://example.com/"
    assert validator.normalize_url("https://example.com:443/test") == "https://example.com/test"
    assert validator.normalize_url("example.com/test?q=1") == "http://example.com/test?q=1"
    
    # Malformed / Unsupported scheme
    with pytest.raises(ValueError):
        validator.normalize_url("ftp://example.com")

def test_localhost_check():
    validator = TargetValidator()
    
    assert validator.is_localhost("http://localhost:5000") is True
    assert validator.is_localhost("https://127.0.0.1/index") is True
    assert validator.is_localhost("http://[::1]:8080/") is True
    assert validator.is_localhost("https://google.com") is False

def test_scope_restriction():
    validator = TargetValidator()
    
    base = "http://example.com/api"
    assert validator.is_in_scope("http://example.com/api/users", base) is True
    assert validator.is_in_scope("https://example.com/api/users", base) is False  # different scheme
    assert validator.is_in_scope("http://sub.example.com/api", base) is False     # different subdomain
    assert validator.is_in_scope("http://google.com", base) is False

def test_lab_mode_restrictions():
    # Lab mode on localhost -> Allowed
    validator_lab = TargetValidator(mode="lab")
    assert validator_lab.validate_target("http://127.0.0.1:5000") == "http://127.0.0.1:5000/"
    
    # Lab mode on public target -> Blocked
    with pytest.raises(ValueError):
        validator_lab.validate_target("https://google.com")

def test_url_validation_edge_cases():
    validator = TargetValidator()
    with pytest.raises(ValueError):
        validator.normalize_url("")
    with pytest.raises(ValueError):
        validator.normalize_url("http://")
    with pytest.raises(ValueError):
        # Malformed scheme or missing hostname
        validator.normalize_url("http:///test")

def test_localhost_dns_resolution_spoofing():
    from unittest.mock import patch
    validator = TargetValidator()
    
    with patch('socket.gethostbyname') as mock_dns:
        mock_dns.return_value = "127.0.0.1"
        assert validator.is_localhost("http://local-spoof.com/") is True
        
        # Test lab mode validation allows it because it resolves to localhost
        validator_lab = TargetValidator(mode="lab")
        assert validator_lab.validate_target("http://local-spoof.com/") == "http://local-spoof.com/"

    with patch('socket.gethostbyname') as mock_dns:
        mock_dns.return_value = "8.8.8.8"
        assert validator.is_localhost("http://local-spoof.com/") is False
        
        # Test lab mode validation blocks it because it resolves to a public IP
        validator_lab = TargetValidator(mode="lab")
        with pytest.raises(ValueError):
            validator_lab.validate_target("http://local-spoof.com/")

def test_redirect_scope_boundaries():
    validator = TargetValidator()
    # Target is local. Redirecting to google.com is out of scope.
    assert validator.is_in_scope("https://google.com/", "http://127.0.0.1:5000/") is False
    
    # Target is public. Redirecting to localhost is out of scope.
    assert validator.is_in_scope("http://127.0.0.1:5000/", "https://example.com/") is False
