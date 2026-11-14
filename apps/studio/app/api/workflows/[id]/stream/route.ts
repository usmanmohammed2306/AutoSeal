import { NextRequest, NextResponse } from "next/server";
import { API_URL } from "@/lib/api";

export const dynamic = "force-dynamic";

export async function GET(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  const after = request.headers.get("last-event-id") ?? request.nextUrl.searchParams.get("after_id") ?? "0";
  if (!/^[0-9a-f-]{36}$/.test(id) || !/^[0-9]{1,15}$/.test(after)) {
    return NextResponse.json({ error: "Invalid stream identity or cursor" }, { status: 400 });
  }
  try {
    const token = process.env.AUTOSEAL_API_TOKEN;
    const response = await fetch(`${API_URL}/api/workflows/${id}/stream?after_id=${after}`, {
      cache: "no-store", headers: token ? { Authorization: `Bearer ${token}` } : {}, signal: request.signal,
    });
    if (!response.ok) return NextResponse.json({ error: "Workflow stream unavailable" }, { status: response.status });
    return new NextResponse(response.body, { headers: { "Content-Type": "text/event-stream",
      "Cache-Control": "no-store", "X-Accel-Buffering": "no" } });
  } catch { return NextResponse.json({ error: "Workflow stream disconnected" }, { status: 503 }); }
}
