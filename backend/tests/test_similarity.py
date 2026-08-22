from backend.app.similarity.engine import SimilarityEngine
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_similarity_engine_search():
    engine = SimilarityEngine()
    results = engine.find_similar_patterns(
        target_path="examples/vulnerable",
        query_snippet="cursor.execute(query)"
    )

    assert len(results) >= 1
    first_match = results[0]
    assert first_match["label"] == "RELATED PATTERN"
    assert "file_path" in first_match
    assert "line_number" in first_match
    assert "code_snippet" in first_match
    assert first_match["similarity_score"] > 0.0


def test_similarity_api_endpoint():
    payload = {
        "target_path": "examples/vulnerable",
        "query_snippet": "os.system(user_input)",
        "top_k": 3
    }
    response = client.post("/api/similarity/search", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    if len(data) > 0:
        assert data[0]["label"] == "RELATED PATTERN"
