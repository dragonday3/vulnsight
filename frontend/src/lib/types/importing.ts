// Mirrors backend/app/schemas/importing.py (Phase 12) by hand.
export interface ImportedScan {
  scan_id: string;
  target_id: string;
  host: string;
}

export interface ImportResult {
  format: "nessus" | "openvas";
  scans: ImportedScan[];
  skipped_hosts: string[];
  findings_imported: number;
  skipped_no_cve: number;
  skipped_informational: number;
  dropped_invalid_cve: number;
}
