import sys
sys.path.insert(0, ".")
from analyzer import JSAnalyzer

def test_aws_key_detection():
    js = 'const k = "AKIAIOSFODNN7EXAMPLE";'
    r = JSAnalyzer("test").analyze(js)
    assert any("AWS" in s["kind"] for s in r["secrets"]) if isinstance(r, dict) else any("AWS" in s.kind for s in r.secrets)

def test_endpoint_extraction():
    from analyzer import JSAnalyzer
    js = 'fetch("/api/v1/users"); axios.get("/api/admin/config")'
    r = JSAnalyzer("test").analyze(js)
    eps = r.endpoints if hasattr(r, "endpoints") else r["endpoints"]
    assert any("/api" in e for e in eps)

def test_s3_bucket_detection():
    js = 'const b = "myapp.s3.amazonaws.com";'
    r = JSAnalyzer("test").analyze(js)
    cloud = r.cloud_assets if hasattr(r, "cloud_assets") else r["cloud_assets"]
    assert len(cloud) >= 1

def test_ssrf_param_classification():
    js = 'fetch("/api?url=x&redirect=y&callback=z")'
    r = JSAnalyzer("test").analyze(js)
    ip = r.interesting_params if hasattr(r, "interesting_params") else r["interesting_params"]
    assert "ssrf" in ip or "redirect" in ip

if __name__ == "__main__":
    test_aws_key_detection()
    test_endpoint_extraction()
    test_s3_bucket_detection()
    test_ssrf_param_classification()
    print("All tests passed.")
