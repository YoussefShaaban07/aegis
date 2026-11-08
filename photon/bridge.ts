/**
 * Aegis <-> Photon Spectrum bridge (iMessage).
 *
 * Aegis is Python; Photon's Spectrum SDK is TypeScript. This small Bun process keeps the Spectrum
 * connection open and listens on 127.0.0.1 only:
 *   POST /send   {to: "+16015550100", text}  -> sends an iMessage        (from Aegis)
 *   GET  /health                             -> {ok, mode}
 * Every inbound iMessage is passed to Aegis (POST {AEGIS_URL}/api/alerts/inbound); Aegis decides
 * what it means (e.g. "ack" acknowledges the open alert) and the bridge sends Aegis's answer back.
 *
 * Credentials come from .env (Bun loads it automatically): PROJECT_ID and PROJECT_SECRET, as written by
 * `bun create spectrum-project ... --projectId <id>`. Requests from Aegis carry X-Aegis-Bridge, an HMAC of
 * the project secret, so another program on the laptop can't send texts through it.
 *
 * Run from the Aegis folder:  bun install --cwd photon  then  bun run photon/bridge.ts
 * Test without Photon:        PHOTON_BRIDGE_FAKE=1 bun run photon/bridge.ts   (prints instead of sending)
 */
import { createHmac, timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PHOTON_BRIDGE_PORT ?? 8789);
const AEGIS = (process.env.AEGIS_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
const FAKE = process.env.PHOTON_BRIDGE_FAKE === "1";
const SECRET = process.env.PROJECT_SECRET ?? process.env.SPECTRUM_PROJECT_SECRET ?? "";
const PROJECT = process.env.PROJECT_ID ?? process.env.SPECTRUM_PROJECT_ID ?? "";
if (!FAKE && (!SECRET || !PROJECT)) {
  console.error("PROJECT_ID / PROJECT_SECRET missing from .env (copy them from the folder `bun create spectrum-project` made).");
  process.exit(1);
}
const TOKEN = createHmac("sha256", SECRET || "fake").update("aegis-bridge").digest("hex");

type Sender = { send(to: string, text: string): Promise<string>; inbound(): AsyncIterable<{ from: string; text: string; reply(t: string): Promise<unknown> }> };

async function realSender(): Promise<Sender> {
  const { Spectrum } = await import("spectrum-ts");
  const { imessage } = await import("spectrum-ts/providers/imessage");
  const app = await Spectrum({ projectId: PROJECT, projectSecret: SECRET, providers: [imessage.config()] });
  const im = imessage(app);
  return {
    async send(to, text) {
      const space = await im.space.create(to);
      const m = await space.send(text);
      return (m as { id?: string } | undefined)?.id ?? "sent";
    },
    async *inbound() {
      for await (const [space, msg] of app.messages) {
        const c = msg.content as { type?: string; text?: string };
        if (msg.direction !== "inbound" || c?.type !== "text" || !c.text) continue;
        yield { from: msg.sender?.id ?? "", text: c.text, reply: (t: string) => space.send(t) };
      }
    },
  };
}

function fakeSender(): Sender {
  const queue: { from: string; text: string; reply(t: string): Promise<unknown> }[] = [];
  let wake: (() => void) | null = null;
  (globalThis as any).__fakeInbound = (from: string, text: string) => {
    queue.push({ from, text, reply: async (t) => console.log(`FAKE-REPLY to ${from}: ${t}`) });
    wake?.();
  };
  return {
    async send(to, text) { console.log(`FAKE-SEND to ${to}: ${text}`); return "fake-1"; },
    async *inbound() {
      while (true) {
        while (queue.length) yield queue.shift()!;
        await new Promise<void>((r) => (wake = r));
      }
    },
  };
}

function authorized(req: Request): boolean {
  const got = Buffer.from(req.headers.get("x-aegis-bridge") ?? "");
  const want = Buffer.from(TOKEN);
  return got.length === want.length && timingSafeEqual(got, want);
}

const sender = FAKE ? fakeSender() : await realSender();

Bun.serve({
  hostname: "127.0.0.1",
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/health") return Response.json({ ok: true, mode: FAKE ? "fake" : "photon" });
    if (!authorized(req)) return Response.json({ ok: false, error: "bad bridge token" }, { status: 401 });
    if (req.method === "POST" && url.pathname === "/send") {
      const { to, text } = (await req.json()) as { to?: string; text?: string };
      if (!to || !text) return Response.json({ ok: false, error: "to and text required" }, { status: 400 });
      try {
        return Response.json({ ok: true, id: await sender.send(to.replace(/\s/g, ""), text.slice(0, 1500)) });
      } catch (e) {
        return Response.json({ ok: false, error: e instanceof Error ? e.message : String(e) }, { status: 502 });
      }
    }
    if (FAKE && req.method === "POST" && url.pathname === "/fake-inbound") {   // tests only
      const { from, text } = (await req.json()) as { from: string; text: string };
      (globalThis as any).__fakeInbound(from, text);
      return Response.json({ ok: true });
    }
    return Response.json({ ok: false, error: "not found" }, { status: 404 });
  },
});
console.log(`Aegis iMessage bridge (${FAKE ? "FAKE, prints only" : "Photon Spectrum"}) on http://127.0.0.1:${PORT}; replies go to ${AEGIS}`);

// inbound iMessages -> Aegis; Aegis's answer goes back to the sender
for await (const m of sender.inbound()) {
  try {
    const r = await fetch(`${AEGIS}/api/alerts/inbound`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-aegis-bridge": TOKEN },
      body: JSON.stringify({ from: m.from, text: m.text }),
    });
    const j = (await r.json().catch(() => ({}))) as { reply?: string };
    if (j.reply) await m.reply(j.reply);
  } catch (e) {
    console.error("could not pass a reply to Aegis:", e instanceof Error ? e.message : e);
  }
}
