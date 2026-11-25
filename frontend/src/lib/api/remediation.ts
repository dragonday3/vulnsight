import { request } from "./client";
import type {
  RemediationItemRead,
  RemediationMetrics,
  RemediationUpdate,
} from "@/lib/types/remediation";

export function listRemediationItems(projectId: string): Promise<RemediationItemRead[]> {
  return request<RemediationItemRead[]>(`/projects/${projectId}/remediation/items`);
}

export function getRemediationMetrics(projectId: string): Promise<RemediationMetrics> {
  return request<RemediationMetrics>(`/projects/${projectId}/remediation/metrics`);
}

export function updateRemediationItem(
  itemId: string,
  payload: RemediationUpdate,
): Promise<RemediationItemRead> {
  return request<RemediationItemRead>(`/remediation/items/${itemId}`, {
    method: "PATCH",
    body: JSON.stringify(payload),
  });
}
