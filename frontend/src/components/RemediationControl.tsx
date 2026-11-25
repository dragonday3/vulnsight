"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { updateRemediationItem } from "@/lib/api/remediation";
import type { RemediationItemRead, RemediationState } from "@/lib/types/remediation";

// Analyst moves allowed by the backend; "verified" only ever comes from a rescan.
const NEXT: Record<RemediationState, { state: RemediationState; label: string }[]> = {
  open: [
    { state: "accepted", label: "Accept risk" },
    { state: "fixed", label: "Mark fixed" },
  ],
  accepted: [{ state: "open", label: "Reopen" }],
  fixed: [{ state: "open", label: "Reopen" }],
  verified: [],
};

export default function RemediationControl({ item }: { item: RemediationItemRead }) {
  const router = useRouter();
  const [note, setNote] = useState(item.note ?? "");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const moves = NEXT[item.state];
  if (moves.length === 0) {
    return <span className="text-xs text-zinc-400">rescan-verified</span>;
  }

  async function move(state: RemediationState) {
    if (state === "accepted" && note.trim() === "") {
      setError("Give a reason to accept the risk.");
      return;
    }
    setIsSubmitting(true);
    setError(null);
    try {
      await updateRemediationItem(item.id, {
        state,
        note: note.trim() === "" ? null : note.trim(),
      });
      router.refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Update failed.");
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="flex flex-col gap-1">
      <input
        type="text"
        value={note}
        onChange={(event) => setNote(event.target.value)}
        disabled={isSubmitting}
        placeholder="Note / reason"
        className="w-36 rounded border border-zinc-300 px-1.5 py-0.5 text-xs text-zinc-700"
      />
      <div className="flex gap-1">
        {moves.map((m) => (
          <button
            key={m.state}
            type="button"
            onClick={() => move(m.state)}
            disabled={isSubmitting}
            className="rounded bg-zinc-800 px-1.5 py-0.5 text-xs text-white disabled:opacity-60"
          >
            {m.label}
          </button>
        ))}
      </div>
      {error && <span className="text-xs text-red-600">{error}</span>}
    </div>
  );
}
