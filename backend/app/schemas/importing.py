import uuid

from pydantic import BaseModel


class ImportedScan(BaseModel):
    scan_id: uuid.UUID
    target_id: uuid.UUID
    host: str


class ImportResult(BaseModel):
    format: str
    scans: list[ImportedScan]
    skipped_hosts: list[str]
    findings_imported: int
    skipped_no_cve: int
    skipped_informational: int
    dropped_invalid_cve: int
