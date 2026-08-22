from typing import List, Optional
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from backend.app.similarity.engine import SimilarityEngine

router = APIRouter(prefix="/similarity", tags=["Similarity Search"])


class SimilaritySearchRequest(BaseModel):
    target_path: str = Field(..., description="Project directory to search within")
    query_snippet: str = Field(..., description="Source code snippet to match against")
    query_file_path: Optional[str] = Field("", description="Source file path of query")
    top_k: Optional[int] = Field(4, description="Maximum number of related patterns to return")


class RelatedPatternSchema(BaseModel):
    file_path: str
    line_number: int
    code_snippet: str
    similarity_score: float
    label: str = "RELATED PATTERN"


@router.get("/status")
def similarity_status():
    return {
        "status": "active",
        "engine": "TF-IDF / Vector Cosine Similarity",
        "labelling": "RELATED PATTERN"
    }


@router.post("/search", response_model=List[RelatedPatternSchema])
def search_similar_patterns(request: SimilaritySearchRequest):
    try:
        engine = SimilarityEngine()
        results = engine.find_similar_patterns(
            target_path=request.target_path,
            query_snippet=request.query_snippet,
            query_file_path=request.query_file_path or "",
            top_k=request.top_k or 4
        )
        return results
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Similarity search failed: {str(e)}")
