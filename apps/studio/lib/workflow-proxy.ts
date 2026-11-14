import { NextRequest, NextResponse } from "next/server";
import { API_URL } from "./api";

export async function workflowMutation(request: NextRequest, path: string) {
  // Do not let another website use the browser's Studio credentials to submit.
  const host = request.headers.get("host") ?? "";
  const localOrigin = /^(127\.0\.0\.1|localhost|\[::1\]):[0-9]{1,5}$/.test(host) ? `http://${host}` : null;
  const expectedOrigin = process.env.AUTOSEAL_STUDIO_ORIGIN ?? localOrigin;
  if (!expectedOrigin || request.headers.get("origin") !== expectedOrigin) {
    return NextResponse.json({ error: "Same-origin request required" }, { status: 403 });
  }
  const reader = process.env.AUTOSEAL_STUDIO_READ_ONLY === "true";
  if (reader) return NextResponse.json({ error: "Read-only Studio" }, { status: 403 });
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(declared) || declared > 65536) return new NextResponse(null, { status: 413 });
  const chunks: Uint8Array[] = []; let size = 0;
  const stream = request.body?.getReader();
  if (stream) {
    while (true) {
      const { value, done } = await stream.read();
      if (done) break;
      size += value.length;
      if (size > 65536) { await stream.cancel(); return new NextResponse(null, { status: 413 }); }
      chunks.push(value);
    }
  }
  const body = new Uint8Array(size); let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  const token = process.env.AUTOSEAL_API_TOKEN;
  try {
    const response = await fetch(`${API_URL}${path}`, { method: "POST", cache: "no-store",
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: body.length ? new TextDecoder().decode(body) : "{}", signal: AbortSignal.timeout(10000) });
    return new NextResponse(await response.text(), { status: response.status,
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  } catch { return NextResponse.json({ error: "Worker API unavailable" }, { status: 503 }); }
}
