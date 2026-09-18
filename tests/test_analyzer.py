import io

from docx import Document
from fastapi.testclient import TestClient

from dlp_gateway.parsing import MAX_BYTES
from dlp_gateway.worker import create_worker_app


def test_health():
    with TestClient(create_worker_app()) as client:
        assert client.get("/health").json() == {"status": "ok", "role": "analyzer"}


def test_docx_extraction_and_signals():
    document = Document()
    document.add_paragraph("Synthetic document: Call 13800138000")
    data = io.BytesIO()
    document.save(data)

    with TestClient(create_worker_app()) as client:
        response = client.post("/analyze", files={"file": ("synthetic.docx", data.getvalue())})

    result = response.json()
    assert response.status_code == 200
    assert result["parser_status"] == "ok"
    assert "phone_candidate" in result["signals"]
    assert "Synthetic document" in result["text"]


def test_invalid_and_blank_inputs_fail_closed():
    with TestClient(create_worker_app()) as client:
        invalid = client.post("/analyze", files={"file": ("broken.pdf", b"not a pdf")})
        blank = client.post("/analyze", files={"file": ("blank.txt", b"  \n")})

    assert invalid.json()["parser_status"] == "unparseable"
    assert blank.json()["parser_status"] == "empty"


def test_size_limit():
    with TestClient(create_worker_app()) as client:
        response = client.post("/analyze", files={"file": ("large.txt", b"x" * (MAX_BYTES + 1))})

    assert response.status_code == 413
