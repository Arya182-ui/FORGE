import type { ScanReport, RuleMetadata } from '../types/scan';

const API_BASE_URL = 'http://localhost:8000';

export interface RelatedPattern {
  file_path: string;
  line_number: number;
  code_snippet: string;
  similarity_score: number;
  label: string;
}

export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/health`);
    if (!res.ok) return false;
    const data = await res.json();
    return data.status === 'healthy';
  } catch {
    return false;
  }
}

export async function triggerLocalScan(targetPath: string, language?: string): Promise<ScanReport> {
  const payload: { target_path: string; language?: string } = { target_path: targetPath };
  if (language && language !== 'all') {
    payload.language = language;
  }

  const res = await fetch(`${API_BASE_URL}/api/scans`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errData = await res.json().catch(() => ({ detail: 'Failed to run scan' }));
    throw new Error(errData.detail || 'Scan execution failed');
  }

  return await res.json();
}

export async function fetchRules(): Promise<RuleMetadata[]> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/rules`);
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}

export async function fetchSimilarPatterns(targetPath: string, snippet: string, filePath: string): Promise<RelatedPattern[]> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/similarity/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_path: targetPath,
        query_snippet: snippet,
        query_file_path: filePath,
        top_k: 3
      }),
    });
    if (!res.ok) return [];
    return await res.json();
  } catch {
    return [];
  }
}
