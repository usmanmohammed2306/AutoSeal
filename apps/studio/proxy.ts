import { NextRequest, NextResponse } from "next/server";

async function equal(a: string, b: string) {
  const encode = new TextEncoder();
  const [x, y] = await Promise.all([a, b].map(value => crypto.subtle.digest("SHA-256", encode.encode(value))));
  const left = new Uint8Array(x), right = new Uint8Array(y);
  let difference = 0;
  for (let i = 0; i < left.length; i++) difference |= left[i] ^ right[i];
  return difference === 0;
}

export async function proxy(request: NextRequest) {
  const user = process.env.AUTOSEAL_STUDIO_USER, password = process.env.AUTOSEAL_STUDIO_PASSWORD;
  if (!user && !password && !process.env.AUTOSEAL_API_TOKEN) return NextResponse.next();
  if (!user || !password || password.length < 16) {
    return NextResponse.json({ error: "Studio authentication is not configured" }, { status: 503 });
  }
  const expected = `Basic ${btoa(`${user}:${password}`)}`;
  if (!await equal(request.headers.get("authorization") ?? "", expected)) {
    return new NextResponse("Authentication required", { status: 401,
      headers: { "WWW-Authenticate": 'Basic realm="AutoSeal Studio", charset="UTF-8"', "Cache-Control": "no-store" } });
  }
  return NextResponse.next();
}

export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
