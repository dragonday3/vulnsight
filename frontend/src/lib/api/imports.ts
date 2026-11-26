import { request } from "./client";
import type { ImportResult } from "@/lib/types/importing";

// The body is the raw report file (.nessus v2 or OpenVAS XML), not JSON and
// not multipart: the backend reads it as-is with a 20 MB cap.
export function importReport(projectId: string, file: File): Promise<ImportResult> {
  return request<ImportResult>(`/projects/${projectId}/imports`, {
    method: "POST",
    headers: { "Content-Type": "application/xml" },
    body: file,
  });
}
