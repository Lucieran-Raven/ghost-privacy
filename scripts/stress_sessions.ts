import { performance } from 'node:perf_hooks';

type JsonValue = null | boolean | number | string | JsonValue[] | { [k: string]: JsonValue };

type StepName = 'create' | 'validate' | 'extend' | 'delete';

type StepResult = {
  step: StepName;
  ok: boolean;
  status: number;
  ms: number;
  code?: string;
};

type SessionBundle = {
  sessionId: string;
  capabilityToken: string;
};

type HttpJsonResult<T> = { status: number; json?: T; text?: string };

function parseArgs(argv: string[]) {
  const out: Record<string, string> = {};
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (!a) continue;
    if (!a.startsWith('--')) continue;
    const k = a.slice(2);
    const v = argv[i + 1];
    if (!v || v.startsWith('--')) {
      out[k] = 'true';
    } else {
      out[k] = v;
      i++;
    }
  }
  return out;
}

function randomAlnumUpper(len: number): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s = '';
  for (let i = 0; i < len; i++) {
    s += chars[Math.floor(Math.random() * chars.length)];
  }
  return s;
}

function makeSessionId(): string {
  return `GHOST-${randomAlnumUpper(4)}-${randomAlnumUpper(4)}`;
}

function makeIp(n: number): string {
  // 10.(0..255).(0..255).(1..254)
  const a = (n >> 16) & 0xff;
  const b = (n >> 8) & 0xff;
  const c = n & 0xff;
  const d = ((n * 73) % 253) + 1;
  return `10.${a}.${b}.${Math.max(1, Math.min(254, d))}`;
}

function sleep(ms: number) {
  return new Promise<void>((r) => setTimeout(r, ms));
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[idx] ?? 0;
}

function summarizeLatencies(values: number[]) {
  const s = [...values].sort((a, b) => a - b);
  const sum = s.reduce((acc, v) => acc + v, 0);
  return {
    count: s.length,
    avg: s.length ? sum / s.length : 0,
    p50: percentile(s, 50),
    p95: percentile(s, 95),
    p99: percentile(s, 99),
    max: s.length ? s[s.length - 1] : 0
  };
}

async function httpJson<T extends JsonValue>(
  url: string,
  init: RequestInit,
  expectJson: boolean,
  timeoutMs: number
): Promise<HttpJsonResult<T>> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    const status = res.status;
    if (!expectJson) {
      return { status, text: await res.text() };
    }
    const text = await res.text();
    try {
      const json = JSON.parse(text) as T;
      return { status, json };
    } catch {
      return { status, text };
    }
  } catch (err: unknown) {
    const anyErr = err as { name?: string; message?: string };
    const msg = typeof anyErr?.message === 'string' ? anyErr.message : String(err);
    const name = typeof anyErr?.name === 'string' ? anyErr.name : '';

    const isTimeout = name === 'AbortError' || /aborted/i.test(msg);
    const code = isTimeout ? 'TIMEOUT' : 'FETCH_FAILED';

    // Treat network/socket failures as a synthetic status=0.
    // This keeps the run alive and lets us measure the scalability cliff.
    return { status: 0, json: { code } as unknown as T, text: msg };
  } finally {
    clearTimeout(timeout);
  }
}

async function runUserFlow(opts: {
  baseUrl: string;
  origin: string;
  apiKey?: string;
  ip: string;
  maxRetries: number;
  retryBaseMs: number;
  timeoutMs: number;
}): Promise<{ steps: StepResult[]; bundle?: SessionBundle } > {
  const steps: StepResult[] = [];

  const commonHeaders: Record<string, string> = {
    'content-type': 'application/json',
    origin: opts.origin,
    'x-forwarded-for': opts.ip
  };
  if (opts.apiKey) {
    commonHeaders.apikey = opts.apiKey;
    commonHeaders.authorization = `Bearer ${opts.apiKey}`;
  }

  const sessionId = makeSessionId();

  // 1) create
  let bundle: SessionBundle | undefined;
  {
    const url = `${opts.baseUrl}/create-session`;
    let attempt = 0;
    while (true) {
      const t0 = performance.now();
      const resp = await httpJson<any>(
        url,
        { method: 'POST', headers: commonHeaders, body: JSON.stringify({ sessionId }) },
        true,
        opts.timeoutMs
      );
      const ms = performance.now() - t0;

      const ok = resp.status >= 200 && resp.status < 300 && resp.json?.success === true;
      const code = typeof resp.json?.code === 'string' ? resp.json.code : undefined;
      steps.push({ step: 'create', ok, status: resp.status, ms, code });

      if (ok) {
        bundle = { sessionId: String(resp.json.sessionId), capabilityToken: String(resp.json.capabilityToken) };
        break;
      }

      // Retry only on 429/503/504 or transient 5xx
      const retryable = resp.status === 0 || resp.status === 429 || resp.status === 503 || resp.status === 504 || (resp.status >= 500 && resp.status < 600);
      if (!retryable || attempt >= opts.maxRetries) {
        return { steps };
      }

      const backoff = opts.retryBaseMs * Math.pow(2, attempt);
      await sleep(backoff);
      attempt++;
    }
  }

  // 2) validate (host)
  {
    const url = `${opts.baseUrl}/validate-session`;
    const t0 = performance.now();
    const resp = await httpJson<any>(
      url,
      {
        method: 'POST',
        headers: commonHeaders,
        body: JSON.stringify({ sessionId: bundle.sessionId, capabilityToken: bundle.capabilityToken, role: 'host' })
      },
      true,
      opts.timeoutMs
    );
    const ms = performance.now() - t0;
    const ok = resp.status >= 200 && resp.status < 300 && resp.json?.valid === true;
    const code = typeof resp.json?.code === 'string' ? resp.json.code : undefined;
    steps.push({ step: 'validate', ok, status: resp.status, ms, code });
  }

  // 3) extend (usually will not extend unless close to expiry)
  {
    const url = `${opts.baseUrl}/extend-session`;
    const t0 = performance.now();
    const resp = await httpJson<any>(
      url,
      {
        method: 'POST',
        headers: commonHeaders,
        body: JSON.stringify({ sessionId: bundle.sessionId, capabilityToken: bundle.capabilityToken })
      },
      true,
      opts.timeoutMs
    );
    const ms = performance.now() - t0;
    const ok = resp.status >= 200 && resp.status < 300 && resp.json?.success === true;
    const code = typeof resp.json?.code === 'string' ? resp.json.code : undefined;
    steps.push({ step: 'extend', ok, status: resp.status, ms, code });
  }

  // 4) delete
  {
    const url = `${opts.baseUrl}/delete-session`;
    const t0 = performance.now();
    const resp = await httpJson<any>(
      url,
      {
        method: 'POST',
        headers: commonHeaders,
        body: JSON.stringify({ sessionId: bundle.sessionId, capabilityToken: bundle.capabilityToken })
      },
      true,
      opts.timeoutMs
    );
    const ms = performance.now() - t0;
    const ok = resp.status >= 200 && resp.status < 300 && resp.json?.success === true;
    const code = typeof resp.json?.code === 'string' ? resp.json.code : undefined;
    steps.push({ step: 'delete', ok, status: resp.status, ms, code });
  }

  return { steps, bundle };
}

async function main() {
  const args = parseArgs(process.argv);

  const users = Number(args.users ?? '500');
  const concurrency = Number(args.concurrency ?? '500');
  const origin = String(args.origin ?? 'http://localhost:8080');
  const baseUrl = String(args.baseUrl ?? 'http://127.0.0.1:54321/functions/v1');
  const apiKey = args.apiKey ? String(args.apiKey) : undefined;
  const maxRetries = Number(args.maxRetries ?? '3');
  const retryBaseMs = Number(args.retryBaseMs ?? '100');
  const rampMs = Number(args.rampMs ?? '0');
  const timeoutMs = Number(args.timeoutMs ?? '15000');

  if (!Number.isFinite(users) || users <= 0) throw new Error('Invalid --users');
  if (!Number.isFinite(concurrency) || concurrency <= 0) throw new Error('Invalid --concurrency');

  const targetConcurrency = Math.min(users, concurrency);

  console.log(
    JSON.stringify(
      {
        mode: 'stress_sessions',
        users,
        concurrency: targetConcurrency,
        baseUrl,
        origin,
        maxRetries,
        retryBaseMs,
        rampMs,
        timeoutMs
      },
      null,
      2
    )
  );

  const allSteps: StepResult[] = [];

  let nextIndex = 0;
  const startedAt = performance.now();

  async function worker(workerId: number) {
    while (true) {
      const i = nextIndex;
      nextIndex++;
      if (i >= users) return;

      if (rampMs > 0) {
        const delay = Math.floor((i / Math.max(1, users - 1)) * rampMs);
        await sleep(delay);
      }

      const ip = makeIp(i + 1);
      try {
        const out = await runUserFlow({ baseUrl, origin, apiKey, ip, maxRetries, retryBaseMs, timeoutMs });
        allSteps.push(...out.steps);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        allSteps.push({ step: 'create', ok: false, status: 0, ms: 0, code: `UNCAUGHT:${msg}` });
      }
    }
  }

  await Promise.all(Array.from({ length: targetConcurrency }, (_, i) => worker(i)));

  const totalMs = performance.now() - startedAt;

  const stepsByName: Record<StepName, StepResult[]> = {
    create: [],
    validate: [],
    extend: [],
    delete: []
  };
  for (const s of allSteps) stepsByName[s.step].push(s);

  const failures = allSteps.filter((s) => !s.ok);
  const failuresByStep: Record<StepName, number> = {
    create: failures.filter((f) => f.step === 'create').length,
    validate: failures.filter((f) => f.step === 'validate').length,
    extend: failures.filter((f) => f.step === 'extend').length,
    delete: failures.filter((f) => f.step === 'delete').length
  };

  const failureCodes: Record<string, number> = {};
  for (const f of failures) {
    const key = `${f.step}:${f.status}:${f.code ?? 'NO_CODE'}`;
    failureCodes[key] = (failureCodes[key] ?? 0) + 1;
  }

  const report = {
    users,
    concurrency: targetConcurrency,
    totalMs,
    steps: {
      create: {
        total: stepsByName.create.length,
        failures: failuresByStep.create,
        latencyMs: summarizeLatencies(stepsByName.create.map((s) => s.ms))
      },
      validate: {
        total: stepsByName.validate.length,
        failures: failuresByStep.validate,
        latencyMs: summarizeLatencies(stepsByName.validate.map((s) => s.ms))
      },
      extend: {
        total: stepsByName.extend.length,
        failures: failuresByStep.extend,
        latencyMs: summarizeLatencies(stepsByName.extend.map((s) => s.ms))
      },
      delete: {
        total: stepsByName.delete.length,
        failures: failuresByStep.delete,
        latencyMs: summarizeLatencies(stepsByName.delete.map((s) => s.ms))
      }
    },
    failureCounts: {
      totalFailures: failures.length,
      byStep: failuresByStep,
      byCode: failureCodes
    }
  };

  console.log(JSON.stringify(report, null, 2));

  // Fail the process if we saw any failures.
  if (failures.length > 0) {
    process.exitCode = 2;
  }
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
