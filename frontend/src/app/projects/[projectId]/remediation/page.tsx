import Link from "next/link";
import { notFound } from "next/navigation";
import RemediationControl from "@/components/RemediationControl";
import SeverityBadge from "@/components/SeverityBadge";
import { getProject } from "@/lib/api/projects";
import { getRemediationMetrics, listRemediationItems } from "@/lib/api/remediation";
import { listTargets } from "@/lib/api/targets";
import type { Severity } from "@/lib/types/finding";
import type { RemediationItemRead, RemediationMetrics } from "@/lib/types/remediation";

export const dynamic = "force-dynamic";

const STATE_STYLE: Record<string, string> = {
  open: "bg-amber-50 text-amber-800 border-amber-300",
  accepted: "bg-zinc-100 text-zinc-700 border-zinc-300",
  fixed: "bg-sky-50 text-sky-800 border-sky-300",
  verified: "bg-emerald-50 text-emerald-800 border-emerald-300",
};

const REASON_LABEL: Record<string, string> = {
  cve_not_matched: "rescan no longer matches this CVE",
  service_not_observed: "service no longer observed (weaker: could be down)",
};

function days(from: string, to: Date): number {
  return Math.floor((to.getTime() - new Date(from).getTime()) / 86_400_000);
}

function Card({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-zinc-200 bg-white p-4 shadow-sm">
      <span className="text-xs uppercase tracking-wide text-zinc-500">{label}</span>
      <span className="text-2xl font-semibold text-zinc-900">{value}</span>
      {hint && <span className="text-xs text-zinc-500">{hint}</span>}
    </div>
  );
}

export default async function RemediationPage({
  params,
}: PageProps<"/projects/[projectId]/remediation">) {
  const { projectId } = await params;

  let projectName: string;
  try {
    projectName = (await getProject(projectId)).name;
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("API error 404:")) notFound();
    return (
      <div className="min-h-screen bg-zinc-50 p-12 text-center text-sm text-red-700">
        Couldn&apos;t load this project — is the backend running?
      </div>
    );
  }

  let items: RemediationItemRead[] = [];
  let metrics: RemediationMetrics | null = null;
  let loadError: string | null = null;
  try {
    [items, metrics] = await Promise.all([
      listRemediationItems(projectId),
      getRemediationMetrics(projectId),
    ]);
  } catch (err) {
    loadError = err instanceof Error ? err.message : "Failed to load remediation data.";
  }
  const targets = new Map((await listTargets(projectId).catch(() => [])).map((t) => [t.id, t]));
  const now = new Date();

  return (
    <div className="min-h-screen bg-zinc-50">
      <div className="mx-auto flex w-full max-w-5xl flex-col gap-6 px-6 py-12">
        <header className="flex flex-col gap-1">
          <Link href={`/projects/${projectId}`} className="text-sm text-zinc-500 hover:underline">
            &larr; {projectName}
          </Link>
          <h1 className="text-2xl font-semibold text-zinc-900">Remediation</h1>
          <p className="text-sm text-zinc-500">
            One item per vulnerable target, port and CVE, tracked across scans. Deadlines: 15 /
            30 / 90 / 180 days by severity, 14 days for CISA KEV. Only a complete rescan can
            verify a fix.
          </p>
        </header>

        {metrics?.simulated && (
          <p
            role="alert"
            className="rounded-md border-2 border-purple-400 bg-purple-50 px-4 py-3 text-sm font-medium text-purple-900"
          >
            SIMULATED DATA: these items and metrics come from seeded demo data, not real scans.
            They show how the metrics work and are not a measurement.
          </p>
        )}

        {loadError ? (
          <p className="rounded-lg border border-red-200 bg-red-50 px-4 py-6 text-center text-sm text-red-700">
            Couldn&apos;t load remediation data — is the backend running?
          </p>
        ) : (
          metrics && (
            <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Card
                label="Unresolved"
                value={String(metrics.by_state.open + metrics.by_state.fixed)}
                hint={`${metrics.by_state.accepted} risk-accepted, ${metrics.by_state.verified} verified`}
              />
              <Card label="Overdue now" value={String(metrics.overdue_now)} />
              <Card
                label="SLA breach"
                value={metrics.sla_breach_pct == null ? "—" : `${metrics.sla_breach_pct}%`}
              />
              <Card
                label="MTTR"
                value={metrics.mttr_days == null ? "—" : `${metrics.mttr_days} d`}
                hint="first seen → verified"
              />
              <div className="col-span-2 rounded-lg border border-zinc-200 bg-white p-4 text-sm shadow-sm sm:col-span-4">
                <span className="text-xs uppercase tracking-wide text-zinc-500">
                  Aging of unresolved items (days since first seen)
                </span>
                <div className="mt-2 flex gap-6">
                  {Object.entries(metrics.aging_unresolved).map(([bucket, count]) => (
                    <span key={bucket} className="text-zinc-700">
                      <span className="font-semibold">{count}</span> {bucket}
                    </span>
                  ))}
                </div>
              </div>
            </section>
          )
        )}

        {!loadError && items.length === 0 ? (
          <p className="rounded-lg border border-dashed border-zinc-300 px-4 py-6 text-center text-sm text-zinc-500">
            No remediation items yet. Items are created when an Nmap scan matches CVEs.
          </p>
        ) : (
          <div className="overflow-x-auto rounded-lg border border-zinc-200 bg-white shadow-sm">
            <table className="w-full text-left text-sm">
              <thead className="bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
                <tr>
                  <th className="px-3 py-2 font-medium">CVE</th>
                  <th className="px-3 py-2 font-medium">Where</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">State</th>
                  <th className="px-3 py-2 font-medium">Due</th>
                  <th className="px-3 py-2 font-medium">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100">
                {items.map((item) => {
                  const unresolved = item.state === "open" || item.state === "fixed";
                  const overdue = unresolved && new Date(item.due_at) < now;
                  return (
                    <tr key={item.id} className="align-top">
                      <td className="px-3 py-2">
                        <a
                          href={`https://nvd.nist.gov/vuln/detail/${item.cve_id}`}
                          target="_blank"
                          rel="noreferrer"
                          className="font-mono text-xs text-blue-700 hover:underline"
                        >
                          {item.cve_id}
                        </a>
                        {item.kev && (
                          <span className="ml-1 rounded border border-red-300 bg-red-50 px-1 text-xs text-red-800">
                            KEV
                          </span>
                        )}
                        {item.simulated && (
                          <span className="ml-1 rounded border border-purple-300 bg-purple-50 px-1 text-xs text-purple-800">
                            simulated
                          </span>
                        )}
                      </td>
                      <td className="px-3 py-2 text-xs text-zinc-700">
                        {targets.get(item.target_id)?.value ?? item.target_id.slice(0, 8)}:
                        {item.port}/{item.protocol}
                      </td>
                      <td className="px-3 py-2">
                        <SeverityBadge severity={item.severity as Severity} />
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`rounded border px-1.5 py-0.5 text-xs ${STATE_STYLE[item.state]}`}
                        >
                          {item.state}
                        </span>
                        {item.verification_reason && (
                          <div className="mt-1 text-xs text-zinc-500">
                            {REASON_LABEL[item.verification_reason] ?? item.verification_reason}
                          </div>
                        )}
                        {item.reopened_count > 0 && (
                          <div className="mt-1 text-xs text-amber-700">
                            reopened {item.reopened_count}×
                          </div>
                        )}
                        {item.note && (
                          <div className="mt-1 max-w-48 text-xs text-zinc-500">“{item.note}”</div>
                        )}
                      </td>
                      <td className="px-3 py-2 text-xs">
                        <span className={overdue ? "font-semibold text-red-700" : "text-zinc-700"}>
                          {item.due_at.slice(0, 10)}
                        </span>
                        <div className="text-zinc-500">
                          {overdue
                            ? `${days(item.due_at, now)} d overdue`
                            : `age ${days(item.first_seen_at, now)} d`}
                        </div>
                      </td>
                      <td className="px-3 py-2">
                        <RemediationControl item={item} />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
