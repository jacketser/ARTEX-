import { NextResponse } from "next/server";

// The HttpOnly refresh cookie is scoped to /api/auth and is intentionally absent
// on page requests. The shared client layout restores the session before rendering;
// every API request is independently authenticated by Go, also in static exports.
export function proxy() {
  return NextResponse.next();
}
