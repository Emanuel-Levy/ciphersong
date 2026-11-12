import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from backend_api import app, _is_safe_public_url


@pytest.fixture
def client():
    return TestClient(app)


def test_ssrf_protection_blocks_internal_addresses():
    # Loopback
    is_safe, reason = _is_safe_public_url("http://127.0.0.1:8080/cifra")
    assert not is_safe
    assert "não permitido" in reason or "SSRF" in reason

    # Localhost
    is_safe, reason = _is_safe_public_url("http://localhost/secret")
    assert not is_safe

    # Invalid scheme
    is_safe, reason = _is_safe_public_url("ftp://cifraclub.com.br")
    assert not is_safe
    assert "Protocolo inválido" in reason


def test_importar_link_ssrf_rejection(client):
    auth_header = {"Authorization": "Bearer mock-token-test"}
    with patch("backend_api.require_authenticated_user", return_value="user_test_1"):
        resp = client.post(
            "/api/musicas/importar-link",
            headers=auth_header,
            json={"url": "http://127.0.0.1/admin"},
        )
        assert resp.status_code == 400
        assert "não permitido" in resp.json()["detail"] or "SSRF" in resp.json()["detail"]


def test_importar_link_parses_html(client):
    auth_header = {"Authorization": "Bearer mock-token-test"}
    mock_html = """
    <html>
      <head>
        <title>A Casa é Sua - Casa Worship | Cifra Club</title>
      </head>
      <body>
        <h1 class="t1a">A Casa é Sua</h1>
        <h2 class="t3">Casa Worship</h2>
        <div id="cifra_tom"><a>G</a></div>
        <pre>
[Intro] <b>G</b>  <b>C9</b>  <b>G</b>  <b>C9</b>

<b>G</b>
Entra na minha casa
<b>D/F#</b>
Entra na minha vida
        </pre>
      </body>
    </html>
    """

    mock_resp = MagicMock()
    mock_resp.read.return_value = mock_html.encode("utf-8")
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.__enter__.return_value = mock_resp

    with patch("backend_api.require_authenticated_user", return_value="user_test_1"):
        with patch("backend_api._is_safe_public_url", return_value=(True, "")):
            with patch("urllib.request.urlopen", return_value=mock_resp):
                resp = client.post(
                    "/api/musicas/importar-link",
                    headers=auth_header,
                    json={"url": "https://example.com/cifra/casa-worship/a-casa-e-sua"},
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["titulo"] == "A Casa é Sua"
                assert data["cantor_principal"] == "Casa Worship"
                assert data["tom_original"] == "G"
                assert "Entra na minha casa" in data["cifra"]
                assert "D/F#" in data["cifra"]


def test_robots_txt_endpoint(client):
    resp = client.get("/robots.txt")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers.get("content-type", "")
    assert "User-agent: *" in resp.text
    assert "Disallow: /api/" in resp.text
    assert "Sitemap: https://ciphersong.com.br/sitemap.xml" in resp.text


def test_sitemap_xml_endpoint(client):
    resp = client.get("/sitemap.xml")
    assert resp.status_code == 200
    assert "application/xml" in resp.headers.get("content-type", "")
    assert "<loc>https://ciphersong.com.br/</loc>" in resp.text
    assert "<loc>https://ciphersong.com.br/repertorio</loc>" in resp.text
