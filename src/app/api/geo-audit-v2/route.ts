import type { NextRequest } from "next/server";
import { POST as runGeoAudit } from "../geo-audit/route";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(request: NextRequest) {
  return runGeoAudit(request);
}
