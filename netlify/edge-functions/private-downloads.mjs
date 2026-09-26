import { getStore } from "npm:@netlify/blobs";

const COOKIE_NAME = "memi_download_access";
const TRACK_HASH = "c0097e66d9ea171e4ad1ddfd8ae09814ec0fddf073c5b2be7a472f29ca853190";
const TRACK_SIZE = 10506533;
const SESSION_SECONDS = 60 * 60 * 24;

const encoder = new TextEncoder();

async function signature(value, password) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return [...new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value)))].map(b => b.toString(16).padStart(2, "0")).join("");
}

function privateResponse(body, status = 200, type = "text/html; charset=utf-8") {
  return new Response(body, { status, headers: { "content-type": type, "cache-control": "private, no-store", "x-content-type-options": "nosniff" } });
}

async function digest(value) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sameValue(left, right) {
  if (!left || !right || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

function readCookie(cookie) {
  return typeof cookie === "string" ? cookie : cookie?.value;
}

function passwordPage(message = "Enter the shared password to access this private area.", error = false) {
  const color = error ? "#ff8c74" : "#d7ff48";
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>MEMI P. — Private access</title><link href="https://fonts.googleapis.com/css2?family=Archivo+Black&family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;600&display=swap" rel="stylesheet"><style>:root{--black:#10100f;--cream:#f2eee7;--acid:#d7ff48;--line:#383834}*{box-sizing:border-box}body{margin:0;min-height:100svh;background:var(--black);color:var(--cream);font-family:'DM Sans',sans-serif;display:grid;place-items:center;padding:24px}.panel{width:min(570px,100%)}.brand{font:24px 'Archivo Black',sans-serif;letter-spacing:-.07em}.eyebrow{color:var(--acid);font:12px 'DM Mono',monospace;text-transform:uppercase;letter-spacing:.14em;margin:70px 0 18px}h1{font:clamp(3.6rem,11vw,6.5rem)/.82 'Archivo Black',sans-serif;letter-spacing:-.1em;margin:0 0 26px}.message{color:${color};font-size:16px;line-height:1.5;margin:0 0 30px}label{display:block;font:11px 'DM Mono',monospace;text-transform:uppercase;letter-spacing:.1em;margin-bottom:9px}input{display:block;width:100%;border:1px solid var(--line);background:transparent;color:var(--cream);padding:16px;font:16px 'DM Sans',sans-serif;outline:none}input:focus{border-color:var(--acid)}button{margin-top:14px;border:0;background:var(--acid);color:var(--black);padding:15px 18px;font:500 11px 'DM Mono',monospace;text-transform:uppercase;letter-spacing:.1em;cursor:pointer}.note{border-top:1px solid var(--line);padding-top:16px;margin-top:52px;color:#817d75;font:11px 'DM Mono',monospace;line-height:1.5;text-transform:uppercase;letter-spacing:.06em}</style></head><body><main class="panel"><div class="brand">MEMI P.</div><div class="eyebrow">Private download room</div><h1>ENTER<br>ACCESS.</h1><p class="message">${message}</p><form action="/downloads/login" method="post"><label for="password">Shared password</label><input id="password" name="password" type="password" required autofocus autocomplete="current-password"><button type="submit">Unlock downloads</button></form><p class="note">Private test area · Access expires after 24 hours</p></main></body></html>`, { status: error ? 401 : 200, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

export default async (request, context) => {
  const url = new URL(request.url);
  const configuredPassword = Netlify.env.get("PROTECTED_PAGE_PASSWORD");

  if (!configuredPassword) return privateResponse("Private downloads are not available yet. Please try again later.", 503);

  if (request.method === "POST" && request.headers.get("origin") !== url.origin) return privateResponse("Forbidden", 403);

  const expectedToken = await digest(`memi-p-downloads:${configuredPassword}`);

  if (url.pathname === "/downloads/login" && request.method === "POST") {
    const form = await request.formData();
    const candidate = await digest(`memi-p-downloads:${String(form.get("password") || "")}`);
    if (!sameValue(candidate, expectedToken)) return passwordPage("Incorrect password. Please try again.", true);
    const session = `${Math.floor(Date.now() / 1000) + SESSION_SECONDS}.${crypto.randomUUID()}`;
    context.cookies.set({ name: COOKIE_NAME, value: `${session}.${await signature(session, configuredPassword)}`, httpOnly: true, secure: true, sameSite: "strict", path: "/downloads", maxAge: SESSION_SECONDS });
    return new Response(null, { status: 303, headers: { location: "/downloads/", "cache-control": "no-store" } });
  }

  if (url.pathname === "/downloads/logout" && request.method === "POST") {
    context.cookies.delete({ name: COOKIE_NAME, path: "/downloads" });
    return Response.redirect(new URL("/downloads/", request.url), 303);
  }

  const parts = (readCookie(context.cookies.get(COOKIE_NAME)) || "").split(".");
  if (parts.length !== 3 || Number(parts[0]) <= Date.now() / 1000 || !sameValue(parts[2], await signature(`${parts[0]}.${parts[1]}`, configuredPassword))) return passwordPage();

  if (url.pathname === "/downloads/higher.mp3") {
    if (request.method !== "GET" && request.method !== "HEAD") return privateResponse("Method not allowed", 405);
    const data = await getStore({ name: "private-music", consistency: "strong" }).get("higher.mp3", { type: "stream" });
    if (!data) return privateResponse("Higher will be available shortly.", 503);
    const response = privateResponse(request.method === "HEAD" ? null : data, 200, "audio/mpeg");
    response.headers.set("Content-Disposition", 'attachment; filename="MEMI P - Higher (Extended Vocal).mp3"');
    return response;
  }

  // Setup accepts only the exact artist-supplied track, never arbitrary files.
  if (url.pathname === "/downloads/setup") {
    if (request.method === "POST") {
      const form = await request.formData();
      const file = form.get("track");
      if (!file || file.size !== TRACK_SIZE) return privateResponse("Select the original Higher MP3.", 400);
      const bytes = await file.arrayBuffer();
      const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(b => b.toString(16).padStart(2, "0")).join("");
      if (hash !== TRACK_HASH) return privateResponse("The file does not match Higher.", 400);
      await getStore({ name: "private-music", consistency: "strong" }).set("higher.mp3", bytes);
      return privateResponse('<p>Higher uploaded successfully.</p><a href="/downloads/">Return to downloads</a>');
    }
    return privateResponse('<!doctype html><html lang="en"><meta name="robots" content="noindex"><title>MEMI P. — Track setup</title><h1>Upload Higher</h1><form method="post" enctype="multipart/form-data"><input type="file" name="track" accept="audio/mpeg" required><button>Upload to private storage</button></form></html>');
  }
  const response = await context.next();
  response.headers.set("Cache-Control", "private, no-store");
  return response;
};

export const config = { path: ["/downloads", "/downloads/*"] };
