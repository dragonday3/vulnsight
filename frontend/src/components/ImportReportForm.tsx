"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState, type FormEvent } from "react";
import { importReport } from "@/lib/api/imports";
import type { ImportResult } from "@/lib/types/importing";

/**
 * Phase 12: upload a Nessus (.nessus v2) or OpenVAS/Greenbone XML report.
 * Hosts are matched to this project's existing targets; unmatched hosts
 * are skipped and listed, never created.
 */
export default function ImportReportForm({ projectId }: { projectId: string }) {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ImportResult | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) {
      setError("Choose a report file first.");
      return;
    }
    setIsSubmitting(true);
    setError(null);
    setResult(null);
    try {
      setResult(await importReport(projectId, file));
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="flex flex-col gap-4 rounded-lg border border-zinc-200 bg-white p-6 shadow-sm"
    >
      <h2 className="text-lg font-semibold text-zinc-900">Import Nessus / OpenVAS report</h2>
      <p className="text-sm text-zinc-500">
        A .nessus (v2) or OpenVAS/Greenbone XML file, up to 20 MB. Hosts must match an existing
        target by IP or hostname; imported findings join the same remediation tracking.
      </p>
      <input
        type="file"
        accept=".nessus,.xml,application/xml,text/xml"
        disabled={isSubmitting}
        onChange={(event) => setFile(event.target.files?.[0] ?? null)}
        className="text-sm text-zinc-700"
      />
      {error && <p className="break-words text-sm text-red-600">{error}</p>}
      {result && (
        <div className="flex flex-col gap-1 text-sm text-zinc-700">
          <p>
            Imported {result.findings_imported} findings from {result.scans.length}{" "}
            {result.scans.length === 1 ? "host" : "hosts"} ({result.format}).
          </p>
          {result.scans.map((s) => (
            <Link
              key={s.scan_id}
              href={`/projects/${projectId}/scans/${s.scan_id}`}
              className="text-zinc-900 underline"
            >
              {s.host}: view imported scan
            </Link>
          ))}
          {result.skipped_hosts.length > 0 && (
            <p className="text-amber-700">
              Skipped (no matching target): {result.skipped_hosts.join(", ")}
            </p>
          )}
          <p className="text-zinc-500">
            Not imported: {result.skipped_no_cve} without a CVE, {result.skipped_informational}{" "}
            informational, {result.dropped_invalid_cve} invalid CVE ids.
          </p>
        </div>
      )}
      <button
        type="submit"
        disabled={isSubmitting}
        className="self-start rounded-md bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-700 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {isSubmitting ? "Importing..." : "Import report"}
      </button>
    </form>
  );
}
