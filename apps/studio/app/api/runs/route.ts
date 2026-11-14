import { NextRequest } from "next/server";
import { workflowMutation } from "@/lib/workflow-proxy";

export async function POST(request: NextRequest) {
  return workflowMutation(request, "/api/runs");
}
