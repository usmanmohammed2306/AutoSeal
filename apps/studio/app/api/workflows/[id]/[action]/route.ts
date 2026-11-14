import { NextRequest, NextResponse } from "next/server";
import { workflowMutation } from "@/lib/workflow-proxy";

export async function POST(request: NextRequest, context: { params: Promise<{ id: string; action: string }> }) {
  const { id, action } = await context.params;
  if (!/^[0-9a-f-]{36}$/.test(id) || !["cancel", "retry"].includes(action)) {
    return NextResponse.json({ error: "Unknown workflow action" }, { status: 400 });
  }
  return workflowMutation(request, `/api/workflows/${id}/${action}`);
}
