import os
import getpass
import platform
import json
import importlib.util

spec = importlib.util.spec_from_file_location("build", "build.py")
build = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build)

def test_redaction():
    user = getpass.getuser()
    host = platform.node()
    root = str(build.ROOT)
    
    # Use raw string for backslashes to avoid escaping issues
    test_str = r"Error in " + root + r"\backend\src. User " + user + r" on host " + host + "."
    
    redacted = build.redact_string(test_str)
    
    if user and user != "REDACTED":
        assert user not in redacted, f"Leaked user: {user}"
    if host and host != "REDACTED":
        assert host not in redacted, f"Leaked host: {host}"
        
    assert root not in redacted, "Leaked root path"
    assert "<repo>/backend/src" in redacted, f"Path not normalized correctly to relative. Got: {redacted}"
    
    print("All diagnostic redaction regression tests PASSED.")

if __name__ == "__main__":
    test_redaction()
