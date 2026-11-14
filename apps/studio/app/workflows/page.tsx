import Link from "next/link";
import { fetchApi, type Workflow } from "@/lib/api";
import { LiveRefresh, WorkflowButton } from "./controls";

export const dynamic = "force-dynamic";

export default async function Workflows() {
  const [cases, rows, access] = await Promise.all([
    fetchApi<{ id: string; task: { operation: string; proxy_mode: string }; origin: string }[]>("/api/cases").catch(() => null),
    fetchApi<Workflow[]>("/api/workflows").catch(() => null),
    fetchApi<{ role: string }>("/api/access").catch(() => null),
  ]);
  const reader = access?.role === "reader" || process.env.AUTOSEAL_STUDIO_READ_ONLY === "true";
  return <div className="page">
    <div className="eyebrow">DURABLE REPAIR WORKFLOWS</div>
    <h1 className="page-title">Follow the evidence.<br /><em>Control the release.</em></h1>
    <p className="lead compact">Validate a registered task, inspect preservation, promote the verified revision, and replay or roll it back. These authored fixed-output cases are separate from external benchmark evidence.</p>
    <LiveRefresh active={!!rows?.some(row => ["RUNNING", "QUEUED", "CANCEL_REQUESTED"].includes(row.state))} />
    <section className="panel wide"><h2>Registered seeded cases</h2>
      {!cases ? <p role="alert">The API is unavailable or access was denied. No case results are inferred.</p> :
        <div className="repair-grid">{cases.map(item => <article className="repair-card" key={item.id}>
          <span className="section-kicker">{item.origin.toUpperCase()} / {item.task.operation}</span><h3>{item.task.proxy_mode.replaceAll("_", " ")}</h3>
          <code>{item.id}</code><p>Three typed plans, eight frozen controls, three sealed repeats, active probes and rollback.</p>
          {!reader && <WorkflowButton label="Validate repair" kind="artifact_validate" payload={{ case: item.id }} />}
        </article>)}</div>}
    </section>
    <section className="panel wide"><h2>Workflow history</h2>
      {rows === null ? <p>History unavailable.</p> : !rows.length ? <p>No workflows submitted. Validation requires a running Mac Docker worker.</p> :
        <table><thead><tr><th>Workflow</th><th>State</th><th>Attempts</th><th>Created</th></tr></thead>
          <tbody>{rows.map(row => <tr key={row.id}><td><Link href={`/workflows/${row.id}`}>{row.kind.replaceAll("artifact_", "")}</Link><br /><code>{row.id.slice(0, 8)}</code></td>
            <td>{row.state}</td><td>{row.attempts} / 3</td><td>{new Date(row.created_at).toLocaleString("en-US")}</td></tr>)}</tbody></table>}
    </section>
  </div>;
}
