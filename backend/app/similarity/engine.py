import math
import re
from pathlib import Path
from typing import List, Dict, Any, Tuple, Set
from backend.app.scanner.file_discovery import FileDiscoveryService


class SimilarityEngine:
    """
    Lightweight, high-performance vector & TF-IDF similarity engine for discovering
    related code patterns across codebase files. Operates 100% offline.
    """
    def __init__(self):
        self.file_discovery = FileDiscoveryService()

    def _tokenize(self, text: str) -> List[str]:
        """Tokenizes code snippet into code identifiers and operators."""
        return [t.lower() for t in re.findall(r"\w+", text) if len(t) >= 2]

    def _compute_tf_idf_vector(self, tokens: List[str], vocabulary: List[str]) -> List[float]:
        """Computes term frequency vector against vocabulary."""
        token_counts = {}
        for t in tokens:
            token_counts[t] = token_counts.get(t, 0) + 1

        vector = []
        for word in vocabulary:
            tf = token_counts.get(word, 0) / max(len(tokens), 1)
            vector.append(tf)
        return vector

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculates cosine similarity between two vectors."""
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm_a = math.sqrt(sum(a * a for a in vec1))
        norm_b = math.sqrt(sum(b * b for b in vec2))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot_product / (norm_a * norm_b)

    def find_similar_patterns(
        self,
        target_path: str,
        query_snippet: str,
        query_file_path: str = "",
        top_k: int = 4
    ) -> List[Dict[str, Any]]:
        """
        Discovers related code patterns across target directory files.
        Results are strictly labeled as 'RELATED PATTERN' per specification.
        """
        discovered_files = self.file_discovery.discover_files(target_path)
        if not discovered_files or not query_snippet.strip():
            return []

        query_tokens = self._tokenize(query_snippet)
        if not query_tokens:
            return []

        # Build corpus of lines/snippets from discovered files
        corpus_items: List[Dict[str, Any]] = []
        vocabulary_set: Set[str] = set(query_tokens)

        for file_path, _ in discovered_files:
            file_str = str(file_path)
            try:
                content = file_path.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
                for idx, line in enumerate(lines, 1):
                    line_clean = line.strip()
                    if len(line_clean) < 10 or line_clean.startswith("#") or line_clean.startswith("//"):
                        continue  # Skip comments or short lines

                    line_tokens = self._tokenize(line_clean)
                    if line_tokens:
                        corpus_items.append({
                            "file_path": file_str,
                            "line_number": idx,
                            "code_snippet": line_clean,
                            "tokens": line_tokens
                        })
                        vocabulary_set.update(line_tokens)
            except Exception:
                continue

        vocabulary = list(vocabulary_set)
        query_vector = self._compute_tf_idf_vector(query_tokens, vocabulary)

        results: List[Dict[str, Any]] = []
        for item in corpus_items:
            # Skip exact same line in query file
            if item["file_path"] == query_file_path and item["code_snippet"] == query_snippet.strip():
                continue

            item_vector = self._compute_tf_idf_vector(item["tokens"], vocabulary)
            score = self._cosine_similarity(query_vector, item_vector)

            if score >= 0.35:  # Similarity threshold
                results.append({
                    "file_path": item["file_path"],
                    "line_number": item["line_number"],
                    "code_snippet": item["code_snippet"],
                    "similarity_score": round(score, 2),
                    "label": "RELATED PATTERN"  # Mandatory label per Section 29
                })

        # Sort by similarity score descending and deduplicate by file/line
        results.sort(key=lambda x: x["similarity_score"], reverse=True)
        
        seen = set()
        deduped = []
        for r in results:
            key = f"{r['file_path']}:{r['line_number']}"
            if key not in seen:
                seen.add(key)
                deduped.append(r)

        return deduped[:top_k]
