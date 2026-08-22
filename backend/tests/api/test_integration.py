"""
Exhaustive ASGI Test Suite for BhashaRakshak API.
"""

import asyncio
import json
from typing import Any, Dict, Optional

from app.main import app
from app.xray.engine import ScamXRayEngine


class ASGIClient:
    """Zero-dependency ASGI Test Client for Starlette/FastAPI."""

    def __init__(self, asgi_app):
        self.app = asgi_app

    async def request(
        self,
        method: str,
        path: str,
        json_data: Optional[Any] = None,
        raw_body: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        req_headers = {"host": "testserver"}
        if headers:
            req_headers.update({k.lower(): v for k, v in headers.items()})

        body_bytes = b""
        if json_data is not None:
            body_bytes = json.dumps(json_data).encode("utf-8")
            req_headers["content-type"] = "application/json"
        elif raw_body is not None:
            body_bytes = raw_body.encode("utf-8")

        req_headers["content-length"] = str(len(body_bytes))
        raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in req_headers.items()]

        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": method.upper(),
            "path": path,
            "raw_path": path.encode("ascii"),
            "query_string": b"",
            "headers": raw_headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 80),
            "scheme": "http",
        }

        response_headers = {}
        response_body = bytearray()
        status_code = [200]

        async def receive():
            return {
                "type": "http.request",
                "body": body_bytes,
                "more_body": False,
            }

        async def send(message):
            if message["type"] == "http.response.start":
                status_code[0] = message["status"]
                for k, v in message.get("headers", []):
                    response_headers[k.decode("latin-1").lower()] = v.decode("latin-1")
            elif message["type"] == "http.response.body":
                response_body.extend(message.get("body", b""))

        await self.app(scope, receive, send)

        parsed_json = None
        if response_body:
            try:
                parsed_json = json.loads(response_body.decode("utf-8"))
            except Exception:
                pass

        return {
            "status_code": status_code[0],
            "headers": response_headers,
            "body": response_body.decode("utf-8", errors="replace"),
            "json": parsed_json,
        }

    async def get(self, path: str, headers=None):
        return await self.request("GET", path, headers=headers)

    async def post(self, path: str, json=None, content=None, headers=None):
        return await self.request("POST", path, json_data=json, raw_body=content, headers=headers)


client = ASGIClient(app)


async def test_analyze_single_sms_success():
    payload = {
        "message": "Dear customer, your SBI account is blocked. Update KYC immediately at bit.ly/sbi-kyc",
        "sender_id": "SBI-ALERT"
    }
    response = await client.post("/api/v1/analyze", json=payload)
    assert response["status_code"] == 200
    data = response["json"]
    
    assert "analysis_id" in data
    assert "risk_score" in data and data["risk_score"] > 50
    assert "risk_level" in data and data["risk_level"] in ["HIGH", "CRITICAL"]
    assert "scam_family" in data and data["scam_family"] == "BANK_KYC"
    assert "language" in data and data["language"] in ["en", "hinglish"]
    assert "original_text" in data and data["original_text"] == payload["message"]
    assert "normalized_text" in data
    assert "decoded_meaning" in data
    assert "manipulation_fingerprint" in data
    assert data["manipulation_fingerprint"]["fear"] > 0.5
    assert "obfuscation_fingerprint" in data
    assert "evidence" in data
    assert "safe_action" in data
    assert "model_version" in data


async def test_analyze_batch_sms_success():
    payload = {
        "messages": [
            "Your FedEx parcel is delayed. Pay customs charge at http://courier-fee.live",
            "Electricity bill unpaid. Power will be cut at 9:30 PM. Call 9876543210 immediately.",
            "OTP for your transaction is 482910. Do not share with anyone.",
        ]
    }
    response = await client.post("/api/v1/analyze/batch", json=payload)
    assert response["status_code"] == 200
    data = response["json"]
    
    assert "results" in data
    assert len(data["results"]) == 3
    assert data["total_processed"] == 3
    assert data["results"][0]["scam_family"] == "COURIER"
    assert data["results"][1]["scam_family"] == "GOVERNMENT"


async def test_get_analysis_by_id():
    payload = {"message": "Urgent lottery prize won! Claim now at http://win-kbc.top"}
    create_res = await client.post("/api/v1/analyze", json=payload)
    assert create_res["status_code"] == 200
    analysis_id = create_res["json"]["analysis_id"]

    get_res = await client.get(f"/api/v1/analysis/{analysis_id}")
    assert get_res["status_code"] == 200
    data = get_res["json"]
    assert data["analysis_id"] == analysis_id
    assert data["scam_family"] == "LOTTERY"


async def test_get_analysis_not_found():
    response = await client.get("/api/v1/analysis/00000000-0000-0000-0000-000000000000")
    assert response["status_code"] == 404


async def test_submit_feedback_success():
    create_res = await client.post("/api/v1/analyze", json={"message": "Work from home daily salary Rs 5000 contact HR"})
    analysis_id = create_res["json"]["analysis_id"]

    feedback_payload = {
        "analysis_id": analysis_id,
        "is_correct": True,
        "comment": "Confirmed Job Scam pattern",
        "analyst_id": "analyst-007"
    }
    response = await client.post("/api/v1/feedback", json=feedback_payload)
    assert response["status_code"] == 201
    data = response["json"]
    assert "feedback_id" in data
    assert data["analysis_id"] == analysis_id
    assert data["status"] == "recorded"


async def test_validation_malformed_json():
    response = await client.post(
        "/api/v1/analyze",
        content="{'broken': json,",
        headers={"Content-Type": "application/json"}
    )
    assert response["status_code"] in [400, 422]


async def test_validation_missing_required_fields():
    response = await client.post("/api/v1/analyze", json={"sender_id": "SBI"})
    assert response["status_code"] == 422


async def test_validation_wrong_types():
    response = await client.post("/api/v1/analyze", json={"message": 123456})
    assert response["status_code"] == 422


async def test_validation_huge_input():
    huge_message = "A" * 5001
    response = await client.post("/api/v1/analyze", json={"message": huge_message})
    assert response["status_code"] == 422


async def test_unicode_and_mixed_script_handling():
    payload = {
        "message": "प्रिय ग्राहक, आपका बिजली कनेक्शन आज रात काट दिया जाएगा। तुरंत भुगतान करें।",
    }
    response = await client.post("/api/v1/analyze", json=payload)
    assert response["status_code"] == 200
    data = response["json"]
    assert data["language"] == "hi"
    assert data["risk_score"] >= 50
    assert data["scam_family"] == "GOVERNMENT"


async def test_concurrent_requests():
    messages = [
        f"Suspicious bank message iteration {i} update KYC http://fake-{i}.top"
        for i in range(20)
    ]
    tasks = [client.post("/api/v1/analyze", json={"message": msg}) for msg in messages]
    responses = await asyncio.gather(*tasks)
    
    assert len(responses) == 20
    for r in responses:
        assert r["status_code"] == 200
        assert "analysis_id" in r["json"]


async def test_duplicate_requests_handling():
    payload = {"message": "Identical test message for deduplication verify."}
    res1 = await client.post("/api/v1/analyze", json=payload)
    res2 = await client.post("/api/v1/analyze", json=payload)
    
    assert res1["status_code"] == 200
    assert res2["status_code"] == 200
    assert res1["json"]["analysis_id"] != res2["json"]["analysis_id"]


async def test_malformed_ai_output_fallback():
    class BrokenLLM:
        def generate(self, prompt: str) -> str:
            return "NOT A VALID JSON AT ALL {broken"

    engine = ScamXRayEngine(llm_client=BrokenLLM())
    result = engine.analyze("Your PAN card is suspended. Click http://pan.xyz")
    assert result.risk_score > 50
    assert result.scam_family.value == "BANK_KYC"


async def test_database_failure_resilience():
    response = await client.get("/api/v1/health")
    assert response["status_code"] == 200
    assert response["json"]["status"] in ["healthy", "degraded"]


async def test_security_headers_present():
    response = await client.get("/api/v1/health")
    assert response["status_code"] == 200
    
    headers = response["headers"]
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "x-request-id" in headers


async def run_all():
    await test_analyze_single_sms_success()
    await test_analyze_batch_sms_success()
    await test_get_analysis_by_id()
    await test_get_analysis_not_found()
    await test_submit_feedback_success()
    await test_validation_malformed_json()
    await test_validation_missing_required_fields()
    await test_validation_wrong_types()
    await test_validation_huge_input()
    await test_unicode_and_mixed_script_handling()
    await test_concurrent_requests()
    await test_duplicate_requests_handling()
    await test_malformed_ai_output_fallback()
    await test_database_failure_resilience()
    await test_security_headers_present()
