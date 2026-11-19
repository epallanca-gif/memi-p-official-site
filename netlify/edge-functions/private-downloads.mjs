import { getStore } from "@netlify/blobs";
import { CHUNK_SIZE, CHUNK_HASHES } from "./wav-chunks.mjs";

const COOKIE_NAME = "memi_download_access";
const TRACKS = [
  { key: "the-light.wav", filename: "MEMI P - The Light.wav", size: 54030318, hash: "3cfd74d608749cc8337cc2b9569f4bd13f2a6ba2dc33084bf3f8ad86cd6216ca" },
  { key: "higher.wav", filename: "MEMI P - Higher.wav", size: 101277234, hash: "6f2015d9fc536ff7089db6ed27fad355afb7d4ab6e27613d189b05cab595d6f3" },
  { key: "boogies-in-my-soul.wav", filename: "MEMI P - Boogie's in My Soul (Extended Mix).wav", size: 73953072, hash: "0f04921dc975bf854530c049a0081e655f131aecc58bfe83b12fa68959c3e80b" },
  { key: "its-our-time-tonight.wav", filename: "MEMI P - It's Our Time Tonight (Vocal Mix).wav", size: 76688376, hash: "38a4ef9d8fdd363f0c783a830ee4c2cc3e10129c98450c2af4cd11a3cf7fa2da" },
];
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

  if (url.pathname === "/downloads/higher.mp3") return privateResponse("This download has been replaced by the WAV collection.", 410);
  const track = TRACKS.find(item => url.pathname === `/downloads/${item.key}`);
  if (track) {
    if (request.method !== "GET" && request.method !== "HEAD") return privateResponse("Method not allowed", 405);
    const store = getStore({ name: "private-music", consistency: "strong" });
    const ready = await store.get(`${track.key}.ready`, { type: "json" });
    let data;
    if (ready?.hash === track.hash) {
      let index = 0;
      data = new ReadableStream({
        async pull(controller) {
          try {
            if (index === CHUNK_HASHES[track.key].length) { controller.close(); return; }
            const part = await store.get(`wav-parts/${track.key}/${index++}`, { type: "arrayBuffer" });
            if (!part) throw new Error("Missing WAV part");
            controller.enqueue(new Uint8Array(part));
          } catch (error) { controller.error(error); }
        }
      });
    } else {
      data = await store.get(track.key, { type: "stream" });
    }
    if (!data) return privateResponse("This track will be available shortly.", 503);
    const response = privateResponse(request.method === "HEAD" ? null : data, 200, "audio/wav");
    response.headers.set("Content-Disposition", `attachment; filename="${track.filename}"`);
    response.headers.set("Content-Length", String(track.size));
    return response;
  }

  if (url.pathname === "/downloads/upload-part" && request.method === "POST") {
    const selected = TRACKS.find(item => item.key === url.searchParams.get("track"));
    const index = Number(url.searchParams.get("part"));
    if (!selected || !Number.isInteger(index) || index < 0 || index >= CHUNK_HASHES[selected.key].length) return privateResponse("Invalid part", 400);
    const bytes = await request.arrayBuffer();
    const expectedSize = Math.min(CHUNK_SIZE, selected.size - index * CHUNK_SIZE);
    if (bytes.byteLength !== expectedSize) return privateResponse("Invalid part size", 400);
    const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(b => b.toString(16).padStart(2, "0")).join("");
    if (hash !== CHUNK_HASHES[selected.key][index]) return privateResponse("Invalid WAV content", 400);
    await getStore({ name: "private-music", consistency: "strong" }).set(`wav-parts/${selected.key}/${index}`, bytes);
    return privateResponse("Part saved", 200, "text/plain");
  }

  if (url.pathname === "/downloads/upload-complete" && request.method === "POST") {
    const selected = TRACKS.find(item => item.key === url.searchParams.get("track"));
    if (!selected) return privateResponse("Invalid track", 400);
    const store = getStore({ name: "private-music", consistency: "strong" });
    const parts = await Promise.all(CHUNK_HASHES[selected.key].map((_, index) => store.getMetadata(`wav-parts/${selected.key}/${index}`)));
    if (!parts.every(Boolean)) return privateResponse("Upload incomplete. Retry the file.", 409);
    await store.setJSON(`${selected.key}.ready`, { hash: selected.hash });
    return privateResponse("WAV uploaded successfully", 200, "text/plain");
  }

  // Setup accepts only the exact artist-supplied track, never arbitrary files.
  if (url.pathname === "/downloads/setup") {
    if (request.method === "POST") {
      const form = await request.formData();
      const file = form.get("track");
      const selected = TRACKS.find(item => item.size === file?.size);
      if (!selected) return privateResponse("Select one of the four original WAV files.", 400);
      const bytes = await file.arrayBuffer();
      const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map(b => b.toString(16).padStart(2, "0")).join("");
      if (hash !== selected.hash) return privateResponse("The file does not match the original WAV.", 400);
      const store = getStore({ name: "private-music", consistency: "strong" });
      await store.set(selected.key, bytes);
      const complete = await Promise.all(TRACKS.map(item => store.getMetadata(item.key)));
      if (complete.every(Boolean)) await store.delete("higher.mp3");
      return privateResponse('<p>WAV uploaded successfully.</p><a href="/downloads/setup">Upload another WAV</a> · <a href="/downloads/">Return to downloads</a>');
    }
    return privateResponse(`<!doctype html><html lang="en"><meta name="robots" content="noindex"><title>MEMI P. — Track setup</title><h1>Upload WAV collection</h1><p>Select one original WAV at a time. Keep this page open until the upload is complete.</p><form><input type="file" name="track" accept=".wav,audio/wav" required><button>Upload to private storage</button></form><p id="status" role="status"></p><a href="/downloads/">Return to downloads</a><script>
    const tracks = ${JSON.stringify(TRACKS.map(({key,size}) => ({key,size})))};
    const form = document.querySelector('form'), status = document.querySelector('#status');
    form.addEventListener('submit', async event => {
      event.preventDefault();
      const file = form.elements.track.files[0], track = tracks.find(t => t.size === file?.size);
      if (!track) { status.textContent = 'Select one of the four original WAV files.'; return; }
      const button = form.querySelector('button'); button.disabled = true;
      try {
        const count = Math.ceil(file.size / ${CHUNK_SIZE});
        for (let part = 0; part < count; part++) {
          status.textContent = 'Uploading ' + file.name + ' — ' + Math.round(part / count * 100) + '%';
          const response = await fetch('/downloads/upload-part?track=' + encodeURIComponent(track.key) + '&part=' + part, { method: 'POST', body: file.slice(part * ${CHUNK_SIZE}, (part + 1) * ${CHUNK_SIZE}) });
          if (!response.ok || (await response.text()) !== 'Part saved') throw new Error('Upload interrupted. Please sign in if needed and retry.');
        }
        const response = await fetch('/downloads/upload-complete?track=' + encodeURIComponent(track.key), {method:'POST'});
        const message = await response.text();
        if (!response.ok || message !== 'WAV uploaded successfully') throw new Error('Could not finish upload. Please retry.');
        status.textContent = file.name + ' — WAV uploaded successfully (100%).';
      } catch (error) { status.textContent = error.message; }
      finally { button.disabled = false; }
    });
    </script></html>`);
  }
  const response = await context.next();
  response.headers.set("Cache-Control", "private, no-store");
  return response;
};

export const config = { path: ["/downloads", "/downloads/*"] };
