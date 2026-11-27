import { NextRequest, NextResponse } from "next/server";
import { lookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 60;

// ---------------------------------------------------------------------------
// Shared types (imported by page)
// ---------------------------------------------------------------------------
export interface CategoryDetail {
  key: string;
  label: string;
  weight: number;
  rawScore: number;
  weightedScore: number;
  maxWeightedScore: number;
  status: "excellent" | "good" | "partial" | "weak" | "missing";
  description: string;
  whyLost: string;
  howToImprove: string;
  expectedGain: number;
  subChecks: SubCheck[];
}

export interface SubCheck {
  key: string;
  label: string;
  status: "pass" | "partial" | "fail";
  impact: "high" | "medium" | "low";
  note: string;
  rating?: "excellent" | "good" | "partial" | "weak" | "missing";
  averageRating?: number;
  sampleCount?: number;
  passCount?: number;
  partialCount?: number;
  failCount?: number;
}

export interface Issue {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  whyItMatters: string;
  recommendedFix: string;
  expectedScoreIncrease: number;
  category: string;
  affectedPages?: string[];
}

export interface QuickWin {
  id: string;
  action: string;
  difficulty: "easy" | "medium" | "hard";
  expectedImpact: "high" | "medium" | "low";
  estimatedTime: string;
  scoreGain: number;
}

export interface PlatformScore {
  id: string;
  name: string;
  score: number;
  status: "compatible" | "partial" | "limited" | "incompatible";
  explanation: string;
  topRecommendation: string;
}

export interface EntityCheck {
  entity: string;
  type: string;
  detected: boolean;
  confidence: number;
  recommendation: string;
}

export interface ContentMetric {
  key: string;
  label: string;
  score: number;
  status: "excellent" | "good" | "partial" | "weak" | "missing";
  explanation: string;
  sampleCount?: number;
}

export interface RoadmapPhase {
  month: string;
  title: string;
  tasks: string[];
  priority: "critical" | "high" | "medium";
  expectedScoreImprovement: number;
}

export interface PageScore {
  url: string;
  visibilityScore: number | null;
  criticalIssues: number;
  priority: "critical" | "high" | "medium" | "low";
  status: "analyzed" | "partial" | "inaccessible";
}

export interface CrawlSummary {
  batchSize: number;
  pagesDiscovered: number;
  pagesAttempted: number;
  pagesAnalyzed: number;
  failedPages: number;
  skippedByRobots: number;
  truncated: boolean;
  subdomainsIncluded: boolean;
  complete?: boolean;
}

export interface AuditResult {
  score: number;
  band: "excellent" | "good" | "fair" | "poor" | "critical";
  citability: number;
  scoreBreakDown: Record<string, number>;
  categoryDetails: CategoryDetail[];
  criticalIssues: Issue[];
  issues: Issue[];
  quickWins: QuickWin[];
  aiPlatforms: PlatformScore[];
  entities: EntityCheck[];
  contentMetrics: ContentMetric[];
  roadmap: RoadmapPhase[];
  pagesAnalyzed: PageScore[];
  crawlSummary: CrawlSummary;
  recommendations: string[];
  checkedAt: string;
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------
function normalizeUrl(input: string): string {
  const s = input.trim();
  return /^https?:\/\//i.test(s) ? s : `https://${s}`;
}

const CRAWL_BATCH_SIZE = 20;
const INITIAL_CRAWL_PAGE_LIMIT = 50;
const MAX_DISCOVERED_URLS = 20_000;
const MAX_FETCH_BYTES = 1_000_000;
const MAX_SITEMAP_BYTES = 10_000_000;
const CRAWL_CONCURRENCY = 4;
const CRAWL_MAX_DURATION_MS = 40_000;
const MAX_SITEMAP_FILES = 100;
const CRAWL_USER_AGENT = "GEO-Audit-Bot";

interface CrawlScope {
  rootHost: string;
  includeSubdomains: boolean;
  publicHostCache: Map<string, Promise<ResolvedAddress[] | null>>;
}

interface ResolvedAddress {
  address: string;
  family: number;
}

interface RobotsRule {
  allow: boolean;
  path: string;
}

interface RobotsPolicy {
  rules: RobotsRule[];
  sitemaps: string[];
}

interface CrawledPage {
  url: string;
  html: string;
}

interface CrawlOutcome {
  pages: CrawledPage[];
  failedUrls: string[];
  skippedUrls: string[];
  attemptedUrls: string[];
  discoveredUrls: string[];
  skippedByRobots: number;
  pagesDiscovered: number;
  truncated: boolean;
  hostFiles: Map<string, { robotsTxt: string | null; llmsTxt: string | null; policy: RobotsPolicy }>;
}

function isPublicAddress(address: string): boolean {
  if (isIP(address) === 4) {
    const octets = address.split(".").map(Number);
    if (octets.length !== 4 || octets.some(value => value < 0 || value > 255)) return false;
    const [a, b, c] = octets;
    return !(
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c <= 2) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)
    );
  }

  if (isIP(address) === 6) {
    const groups = address.toLowerCase().split(":");
    const firstGroup = Number.parseInt(groups[0] || "0", 16);
    const secondGroup = Number.parseInt(groups[1] || "0", 16);
    return firstGroup >= 0x2000 && firstGroup <= 0x3fff &&
      firstGroup !== 0x2002 &&
      !(firstGroup === 0x2001 && (secondGroup === 0 || secondGroup === 0x0db8));
  }

  return false;
}

function isHostInScope(hostname: string, scope: CrawlScope): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return host === scope.rootHost ||
    (scope.includeSubdomains && host.endsWith(`.${scope.rootHost}`));
}

async function getPublicAddresses(hostname: string, scope: CrawlScope): Promise<ResolvedAddress[] | null> {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  let check = scope.publicHostCache.get(host);
  if (!check) {
    check = (async () => {
      if (isIP(host)) return isPublicAddress(host) ? [{ address: host, family: isIP(host) }] : null;
      try {
        const addresses = await lookup(host, { all: true, verbatim: true });
        return addresses.length > 0 && addresses.every(({ address }) => isPublicAddress(address))
          ? addresses
          : null;
      } catch {
        return null;
      }
    })();
    scope.publicHostCache.set(host, check);
  }
  return check;
}

async function isSafeTarget(input: string, scope: CrawlScope): Promise<boolean> {
  try {
    const url = new URL(input);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username || url.password ||
      (url.port && url.port !== "80" && url.port !== "443") ||
      !isHostInScope(url.hostname, scope)
    ) return false;
    return (await getPublicAddresses(url.hostname, scope)) !== null;
  } catch {
    return false;
  }
}

async function safeFetch(
  input: string,
  scope: CrawlScope,
  timeoutMs = 9000,
  maxBytes = MAX_FETCH_BYTES,
): Promise<string | null> {
  let currentUrl = input;

  for (let redirects = 0; redirects <= 3; redirects++) {
    if (!(await isSafeTarget(currentUrl, scope))) return null;
    const url = new URL(currentUrl);
    const addresses = await getPublicAddresses(url.hostname, scope);
    if (!addresses || addresses.length === 0) return null;
    const request = url.protocol === "https:" ? httpsRequest : httpRequest;

    try {
      const response = await new Promise<{ body?: string; location?: string } | null>(resolve => {
        let settled = false;
        const timerRef: { id?: ReturnType<typeof setTimeout> } = {};
        const finish = (result: { body?: string; location?: string } | null) => {
          if (settled) return;
          settled = true;
          if (timerRef.id) clearTimeout(timerRef.id);
          resolve(result);
        };
        const req = request(url, {
          headers: {
            "User-Agent": `${CRAWL_USER_AGENT}/3.0 (+https://aibizmod.com)`,
            "Accept": "text/html,application/xhtml+xml,application/xml,text/plain;q=0.9,*/*;q=0.8",
            "Accept-Encoding": "identity",
          },
          lookup: (_hostname, options, callback) => {
            const selected = addresses[0];
            if (typeof options === "object" && options !== null && options.all) {
              callback(null, addresses);
            } else {
              callback(null, selected.address, selected.family);
            }
          },
        }, response => {
          const status = response.statusCode || 0;
          if (status >= 300 && status < 400) {
            const location = response.headers.location;
            response.resume();
            finish(typeof location === "string" ? { location } : null);
            return;
          }
          const contentLength = Number(response.headers["content-length"]);
          const contentEncoding = response.headers["content-encoding"];
          if (status < 200 || status >= 300 || contentLength > maxBytes ||
            (contentEncoding && contentEncoding !== "identity")) {
            response.destroy();
            finish(null);
            return;
          }

          const chunks: Buffer[] = [];
          let bytesRead = 0;
          response.on("data", (chunk: Buffer | string) => {
            const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            bytesRead += buffer.length;
            if (bytesRead > maxBytes) {
              response.destroy();
              finish(null);
            } else {
              chunks.push(buffer);
            }
          });
          response.on("end", () => finish({ body: Buffer.concat(chunks).toString("utf8") }));
          response.on("error", () => finish(null));
        });
        req.on("error", () => finish(null));
        timerRef.id = setTimeout(() => {
          req.destroy();
          finish(null);
        }, timeoutMs);
        req.end();
      });

      if (!response) return null;
      if (response.location) {
        if (redirects === 3) return null;
        currentUrl = new URL(response.location, currentUrl).toString();
        continue;
      }
      return response.body ?? null;
    } catch {
      return null;
    }
  }

  return null;
}

function normalizeCrawlUrl(value: string, baseUrl: string, scope: CrawlScope, allowXml = false): string | null {
  try {
    const url = new URL(value, baseUrl);
    if (
      !["http:", "https:"].includes(url.protocol) ||
      url.username || url.password ||
      (url.port && url.port !== "80" && url.port !== "443") ||
      !isHostInScope(url.hostname, scope) ||
      url.search
    ) return null;

    url.hash = "";
    if (url.pathname !== "/") url.pathname = url.pathname.replace(/\/+$/, "");
    if (/\.(?:css|js|mjs|json|gz|png|jpe?g|gif|webp|svg|ico|pdf|zip|woff2?|ttf|eot|mp[34]|mov)(?:$|\/)/i.test(url.pathname) ||
      (!allowXml && /\.xml(?:$|\/)/i.test(url.pathname))) {
      return null;
    }
    return url.toString();
  } catch {
    return null;
  }
}

function parseRobotsTxt(text: string | null): RobotsPolicy {
  const groups: { agents: string[]; rules: RobotsRule[] }[] = [];
  const sitemaps: string[] = [];
  let current: { agents: string[]; rules: RobotsRule[] } = { agents: [], rules: [] };
  let groupHasRules = false;

  for (const rawLine of (text || "").split(/\r?\n/)) {
    const line = rawLine.split("#", 1)[0].trim();
    const separator = line.indexOf(":");
    if (separator < 0) continue;
    const directive = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (!value) continue;

    if (directive === "sitemap") {
      sitemaps.push(value);
    } else if (directive === "user-agent") {
      if (groupHasRules) {
        groups.push(current);
        current = { agents: [], rules: [] };
        groupHasRules = false;
      }
      current.agents.push(value.toLowerCase());
    } else if ((directive === "allow" || directive === "disallow") && current.agents.length > 0) {
      current.rules.push({ allow: directive === "allow", path: value });
      groupHasRules = true;
    }
  }
  if (current.agents.length > 0) groups.push(current);

  const matchingGroups = groups
    .map(group => ({
      group,
      matchLength: Math.max(0, ...group.agents
        .filter(agent => agent === "*" || CRAWL_USER_AGENT.toLowerCase().includes(agent))
        .map(agent => agent === "*" ? 0 : agent.length)),
    }))
    .filter(({ group }) => group.agents.some(agent => agent === "*" || CRAWL_USER_AGENT.toLowerCase().includes(agent)));
  const bestMatch = Math.max(0, ...matchingGroups.map(({ matchLength }) => matchLength));
  const rules = matchingGroups
    .filter(({ matchLength }) => matchLength === bestMatch)
    .flatMap(({ group }) => group.rules);

  return { rules, sitemaps };
}

function isAllowedByRobots(url: string, policy: RobotsPolicy): boolean {
  let pathname: string;
  try {
    const parsed = new URL(url);
    pathname = `${parsed.pathname}${parsed.search}`;
  } catch {
    return false;
  }

  const matchingRules = policy.rules.filter(rule => {
    const endAnchor = rule.path.endsWith("$");
    const pattern = endAnchor ? rule.path.slice(0, -1) : rule.path;
    const escaped = pattern
      .split("*")
      .map(segment => segment.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*");
    const expression = new RegExp(`^${escaped}${endAnchor ? "$" : ".*$"}`);
    return expression.test(pathname);
  });
  if (matchingRules.length === 0) return true;

  const longestMatch = Math.max(...matchingRules.map(rule => rule.path.replace(/\*|\$$/g, "").length));
  return matchingRules
    .filter(rule => rule.path.replace(/\*|\$$/g, "").length === longestMatch)
    .some(rule => rule.allow);
}

function decodeXmlText(value: string): string {
  return value
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, "\"")
    .replace(/&apos;/gi, "'");
}

function extractSitemapLocs(xml: string, tag: "sitemap" | "url"): string[] {
  const results: string[] = [];
  const blockPattern = new RegExp(`<${tag}\\b[^>]*>([\\s\\S]*?)<\\/${tag}>`, "gi");
  let block: RegExpExecArray | null;
  while ((block = blockPattern.exec(xml)) !== null) {
    const loc = /<loc\b[^>]*>([\s\S]*?)<\/loc>/i.exec(block[1]);
    if (loc) results.push(decodeXmlText(loc[1].trim()));
  }
  return results;
}

function extractPageLinks(html: string, pageUrl: string, scope: CrawlScope): string[] {
  const links: string[] = [];
  const linkPattern = /<a\b[^>]*\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/gi;
  let match: RegExpExecArray | null;
  while ((match = linkPattern.exec(html)) !== null) {
    const href = match[1] || match[2] || match[3];
    if (!href || /^(?:mailto:|tel:|javascript:|data:)/i.test(href)) continue;
    const normalized = normalizeCrawlUrl(href, pageUrl, scope);
    if (normalized) links.push(normalized);
  }
  return links;
}

async function crawlSite(
  startUrl: string,
  scope: CrawlScope,
  requestedUrls?: string[],
  initialPageLimit = INITIAL_CRAWL_PAGE_LIMIT,
): Promise<CrawlOutcome> {
  const startedAt = Date.now();
  const pages: CrawledPage[] = [];
  const failedUrls: string[] = [];
  const skippedUrls: string[] = [];
  const hostFiles = new Map<string, { robotsTxt: string | null; llmsTxt: string | null; policy: RobotsPolicy }>();
  const hostFilePromises = new Map<string, Promise<{ robotsTxt: string | null; llmsTxt: string | null; policy: RobotsPolicy }>>();
  const candidates: string[] = [];
  const seen = new Set<string>();
  let skippedByRobots = 0;
  let truncated = false;

  const getHostFiles = (pageUrl: string) => {
    const origin = new URL(pageUrl).origin;
    let promise = hostFilePromises.get(origin);
    if (!promise) {
      promise = (async () => {
        const robotsTxt = await safeFetch(new URL("/robots.txt", origin).toString(), scope, 3000);
        const policy = parseRobotsTxt(robotsTxt);
        const llmsUrl = new URL("/llms.txt", origin).toString();
        const llmsTxt = isAllowedByRobots(llmsUrl, policy)
          ? await safeFetch(llmsUrl, scope, 3000)
          : null;
        const files = { robotsTxt, llmsTxt, policy };
        hostFiles.set(origin, files);
        return files;
      })();
      hostFilePromises.set(origin, promise);
    }
    return promise;
  };

  const candidateLimit = requestedUrls ? CRAWL_BATCH_SIZE : initialPageLimit;
  const addCandidate = (url: string) => {
    if (seen.has(url)) return;
    if (seen.size >= MAX_DISCOVERED_URLS) {
      truncated = true;
      return;
    }
    seen.add(url);
    if (candidates.length < candidateLimit) candidates.push(url);
  };

  const root = new URL(startUrl);
  if (requestedUrls) {
    for (const requestedUrl of requestedUrls) {
      const normalized = normalizeCrawlUrl(requestedUrl, startUrl, scope);
      if (normalized) addCandidate(normalized);
    }
  } else {
    addCandidate(root.toString());
    const rootFiles = await getHostFiles(root.toString());
    const sitemapQueue = [
      ...rootFiles.policy.sitemaps,
      new URL("/sitemap.xml", root.origin).toString(),
      new URL("/sitemap_index.xml", root.origin).toString(),
    ];
    const seenSitemaps = new Set<string>();
    let sitemapCount = 0;

    while (sitemapQueue.length > 0 && sitemapCount < MAX_SITEMAP_FILES &&
      seen.size < MAX_DISCOVERED_URLS && Date.now() - startedAt < CRAWL_MAX_DURATION_MS) {
      const sitemapUrl = normalizeCrawlUrl(sitemapQueue.shift() || "", root.origin, scope, true);
      if (!sitemapUrl || seenSitemaps.has(sitemapUrl)) continue;
      seenSitemaps.add(sitemapUrl);
      sitemapCount++;
      const sitemapFiles = await getHostFiles(sitemapUrl);
      if (!isAllowedByRobots(sitemapUrl, sitemapFiles.policy)) {
        skippedByRobots++;
        continue;
      }
      const sitemapXml = await safeFetch(sitemapUrl, scope, 5000, MAX_SITEMAP_BYTES);
      if (!sitemapXml) continue;

      for (const child of extractSitemapLocs(sitemapXml, "sitemap")) {
        const normalized = normalizeCrawlUrl(child, sitemapUrl, scope, true);
        if (normalized && !seenSitemaps.has(normalized)) sitemapQueue.push(normalized);
      }
      for (const location of extractSitemapLocs(sitemapXml, "url")) {
        const normalized = normalizeCrawlUrl(location, sitemapUrl, scope);
        if (normalized) addCandidate(normalized);
        if (seen.size >= MAX_DISCOVERED_URLS) {
          truncated = true;
          break;
        }
      }
    }
    if (sitemapQueue.length > 0 || Date.now() - startedAt >= CRAWL_MAX_DURATION_MS) truncated = true;
  }

  let cursor = 0;
  while (cursor < candidates.length && Date.now() - startedAt < CRAWL_MAX_DURATION_MS) {
    const batch = candidates.slice(cursor, cursor + CRAWL_CONCURRENCY);
    cursor += batch.length;
    const results = await Promise.all(batch.map(async pageUrl => {
      const files = await getHostFiles(pageUrl);
      if (!isAllowedByRobots(pageUrl, files.policy)) {
        return { url: pageUrl, html: null, blocked: true };
      }
      const html = await safeFetch(pageUrl, scope, 6000);
      return { url: pageUrl, html, blocked: false };
    }));

    for (const result of results) {
      if (result.blocked) {
        skippedByRobots++;
        skippedUrls.push(result.url);
        continue;
      }
      if (!result.html) {
        failedUrls.push(result.url);
        continue;
      }
      pages.push({ url: result.url, html: result.html });
      for (const link of extractPageLinks(result.html, result.url, scope)) addCandidate(link);
    }
  }

  if (cursor < candidates.length || Date.now() - startedAt >= CRAWL_MAX_DURATION_MS) truncated = true;
  return {
    pages,
    failedUrls,
    skippedUrls,
    attemptedUrls: candidates.slice(0, cursor),
    discoveredUrls: [...seen],
    skippedByRobots,
    pagesDiscovered: seen.size,
    truncated,
    hostFiles,
  };
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------
function stripHtml(html: string): string {
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function extractJsonLd(html: string): string[] {
  const blocks: string[] = [];
  const re = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) blocks.push(m[1].trim());
  return blocks;
}

function hasSchemaType(blocks: string[], type: string): boolean {
  const lo = type.toLowerCase();
  return blocks.some(b => b.toLowerCase().includes('"@type"') && b.toLowerCase().includes(`"${lo}"`));
}

function parseJsonLd(block: string): Record<string, unknown> | null {
  try { return JSON.parse(block) as Record<string, unknown>; }
  catch { return null; }
}

function countProps(obj: Record<string, unknown> | null, ...props: string[]): number {
  if (!obj) return 0;
  return props.filter(p => {
    const v = obj[p];
    return v !== undefined && v !== null && v !== "";
  }).length;
}

function findSchemaNode(blocks: string[], type: string): Record<string, unknown> | null {
  const lo = type.toLowerCase();
  for (const b of blocks) {
    if (!b.toLowerCase().includes(`"${lo}"`)) continue;
    const parsed = parseJsonLd(b);
    if (!parsed) continue;
    if (Array.isArray(parsed["@graph"])) {
      const found = (parsed["@graph"] as Record<string, unknown>[]).find(
        item => String(item["@type"] ?? "").toLowerCase() === lo
      );
      if (found) return found as Record<string, unknown>;
    }
    if (String(parsed["@type"] ?? "").toLowerCase() === lo) return parsed;
  }
  return null;
}

// ---------------------------------------------------------------------------
// Strict quality rating system
// ---------------------------------------------------------------------------
type Rating = "excellent" | "good" | "partial" | "weak" | "missing";

const RATING_PCT: Record<Rating, number> = {
  excellent: 1.0,
  good: 0.75,
  partial: 0.40,
  weak: 0.20,
  missing: 0,
};

function overallRatingFromScore(score: number): CategoryDetail["status"] {
  if (score >= 85) return "excellent";
  if (score >= 65) return "good";
  if (score >= 35) return "partial";
  if (score > 0)   return "weak";
  return "missing";
}

function bandFromScore(score: number): AuditResult["band"] {
  if (score >= 75) return "excellent";
  if (score >= 60) return "good";
  if (score >= 45) return "fair";
  if (score >= 20) return "poor";
  return "critical";
}

// ---------------------------------------------------------------------------
// SubCheck builder
// ---------------------------------------------------------------------------
interface CheckResult { score: SubCheck; pts: number }

function makeCheck(
  key: string,
  label: string,
  rating: Rating,
  maxPts: number,
  impact: "high" | "medium" | "low",
  notes: Record<Rating | "default", string>,
): CheckResult {
  const pct = RATING_PCT[rating];
  const pts = pct * maxPts;
  const status: SubCheck["status"] = rating === "excellent" || rating === "good" ? "pass"
    : rating === "partial" || rating === "weak" ? "partial"
      : "fail";
  const note = notes[rating] ?? notes["default"];
  return { score: { key, label, status, impact, rating, note }, pts };
}

interface ScoreResult { score: number; recs: string[]; subChecks: SubCheck[] }

// ===========================================================================
// CATEGORY 1 — Structured Data & AI Schema  (weight = 30 pts)
// ===========================================================================
function scoreStructuredData(html: string, blocks: string[]): ScoreResult {
  const checks: SubCheck[] = [];
  const recs: string[] = [];
  let rawTotal = 0;

  function add(c: CheckResult): void {
    checks.push(c.score);
    rawTotal += c.pts;
    if (c.score.status === "fail") recs.push(c.score.note);
    else if (c.score.status === "partial") recs.push(`Improve: ${c.score.label}`);
  }

  const orgNode = findSchemaNode(blocks, "Organization") || findSchemaNode(blocks, "LocalBusiness");
  const orgScore = (() => {
    if (!orgNode) return "missing" as Rating;
    const filled = countProps(orgNode, "name", "url", "logo", "sameAs", "contactPoint", "description", "address");
    if (filled >= 5) return "excellent" as Rating;
    if (filled >= 3) return "good" as Rating;
    if (filled >= 2) return "partial" as Rating;
    return "weak" as Rating;
  })();
  add(makeCheck("org", "Organization / LocalBusiness Schema", orgScore, 24, "high", {
    excellent: "Organization schema detected with full properties (logo, sameAs, contactPoint, address) — entity is AI-verifiable.",
    good: "Organization schema present but missing some key properties (logo, sameAs, or contactPoint).",
    partial: "Basic Organization schema found but critically incomplete — missing logo, sameAs, contactPoint, and more.",
    weak: "Minimal Organization schema detected — only 1-2 properties. Incomplete schemas provide little AI value.",
    missing: "No Organization or LocalBusiness schema detected. This is the single most important structured data for AI entity verification. Add it immediately.",
    default: "Organization schema needs improvement.",
  }));

  const faqNode = findSchemaNode(blocks, "FAQPage");
  const faqQCount = (() => {
    if (!faqNode) return 0;
    const me = faqNode["mainEntity"];
    if (Array.isArray(me)) return me.length;
    return 0;
  })();
  const faqRating: Rating = !faqNode ? "missing"
    : faqQCount >= 5 ? "excellent"
      : faqQCount >= 3 ? "good"
        : faqQCount >= 1 ? "partial"
          : "weak";
  add(makeCheck("faq", "FAQPage Schema", faqRating, 20, "high", {
    excellent: `FAQPage schema with ${faqQCount} Q&A pairs — strong AI answer extraction signal.`,
    good: `FAQPage schema with ${faqQCount} Q&A pairs — add 2+ more questions for full marks.`,
    partial: `FAQPage schema found but only ${faqQCount} Q&A pair(s) — AI needs 5+ pairs to reliably cite your content.`,
    weak: "FAQPage schema present but malformed or empty — add properly structured Q&A pairs.",
    missing: "No FAQPage schema detected. FAQ schema is the primary trigger for AI-generated answer inclusions. Add 5+ Q&A pairs immediately.",
    default: "FAQPage schema needs more questions.",
  }));

  const svcNode = findSchemaNode(blocks, "Service");
  const svcRating: Rating = !svcNode ? "missing"
    : countProps(svcNode, "name", "description", "provider", "areaServed") >= 3 ? "excellent"
      : countProps(svcNode, "name", "description", "provider") >= 2 ? "good"
        : "partial";
  add(makeCheck("service", "Service Schema", svcRating, 12, "high", {
    excellent: "Service schema with name, description, provider, and areaServed — AI can accurately categorize your offerings.",
    good: "Service schema present but missing provider or areaServed — add for full AI categorization.",
    partial: "Basic Service schema found but mostly incomplete — add description, provider, and areaServed.",
    weak: "Minimal Service schema detected.",
    missing: "No Service schema detected. Add Service JSON-LD for each core offering with name, description, provider, and areaServed.",
    default: "Service schema needs improvement.",
  }));

  const personNode = findSchemaNode(blocks, "Person");
  const personRating: Rating = !personNode ? "missing"
    : countProps(personNode, "name", "jobTitle", "url", "sameAs", "email", "description") >= 4 ? "excellent"
      : countProps(personNode, "name", "jobTitle", "url") >= 2 ? "good"
        : "partial";
  add(makeCheck("person", "Person / Author Schema", personRating, 12, "high", {
    excellent: "Person schema with name, jobTitle, URL, and sameAs links — strong E-E-A-T author signal.",
    good: "Person schema present but missing sameAs or detailed credentials — add for full AI author recognition.",
    partial: "Basic Person schema found but incomplete — needs jobTitle, URL, and linked profiles.",
    weak: "Minimal Person schema — almost no author information for AI to verify.",
    missing: "No Person schema detected. Author and team entity schema is essential for E-E-A-T and AI credibility. Add Person JSON-LD for founders and authors.",
    default: "Person schema needs improvement.",
  }));

  const wsNode = findSchemaNode(blocks, "WebSite");
  const wsRaw = blocks.find(b => b.toLowerCase().includes('"website"'));
  const wsHasSearch = wsRaw ? wsRaw.includes("SearchAction") : false;
  const wsRating: Rating = !wsNode ? "missing"
    : wsHasSearch && countProps(wsNode, "name", "url") >= 2 ? "excellent"
      : countProps(wsNode, "name", "url") >= 2 ? "good"
        : "partial";
  add(makeCheck("website", "WebSite Schema", wsRating, 8, "medium", {
    excellent: "WebSite schema with SearchAction, name, and URL — Knowledge Graph eligible.",
    good: "WebSite schema present but missing SearchAction — add for sitelinks search box eligibility.",
    partial: "Incomplete WebSite schema — add name, url, and SearchAction.",
    weak: "Minimal WebSite schema detected.",
    missing: "No WebSite schema. Add WebSite JSON-LD with SearchAction for Knowledge Graph eligibility.",
    default: "WebSite schema needs improvement.",
  }));

  const artNode = findSchemaNode(blocks, "Article") || findSchemaNode(blocks, "BlogPosting");
  const artRating: Rating = !artNode ? "missing"
    : countProps(artNode, "headline", "author", "datePublished", "publisher", "description") >= 4 ? "excellent"
      : countProps(artNode, "headline", "author", "datePublished") >= 2 ? "good"
        : "partial";
  add(makeCheck("article", "Article / BlogPosting Schema", artRating, 8, "medium", {
    excellent: "Article schema with headline, author, datePublished, and publisher — AI can properly attribute content.",
    good: "Article schema present but missing publisher or description — add for full attribution.",
    partial: "Basic Article schema but missing key properties (author, datePublished, publisher).",
    weak: "Minimal Article schema detected.",
    missing: "No Article schema on content pages — add with headline, author, datePublished, and publisher.",
    default: "Article schema needs improvement.",
  }));

  const bcBlock = blocks.find(b => b.toLowerCase().includes('"breadcrumblist"'));
  const bcRating: Rating = !bcBlock ? "missing" : "good";
  add(makeCheck("breadcrumb", "BreadcrumbList Schema", bcRating, 6, "medium", {
    excellent: "BreadcrumbList schema detected — site hierarchy clear for AI.",
    good: "BreadcrumbList schema detected — site hierarchy is crawlable.",
    partial: "BreadcrumbList schema present but may be incomplete.",
    weak: "Minimal BreadcrumbList detected.",
    missing: "No BreadcrumbList schema. Add breadcrumb JSON-LD to all interior pages to clarify site architecture.",
    default: "BreadcrumbList needs improvement.",
  }));

  const revBlock = blocks.find(b => b.toLowerCase().includes('"review"') || b.toLowerCase().includes('"aggregaterating"'));
  const revRating: Rating = !revBlock ? "missing" : "good";
  add(makeCheck("review", "Review / AggregateRating Schema", revRating, 5, "medium", {
    excellent: "Review schema with ratingValue, reviewCount, and author — strong social proof signal.",
    good: "Review or AggregateRating schema detected — social proof is structured.",
    partial: "Review schema found but incomplete.",
    weak: "Minimal review schema detected.",
    missing: "No Review or AggregateRating schema. Add to showcase verified client ratings to AI systems.",
    default: "Review schema needs improvement.",
  }));

  const prodBlock = blocks.find(b => b.toLowerCase().includes('"product"'));
  const prodRating: Rating = !prodBlock ? "missing" : "good";
  add(makeCheck("product", "Product Schema", prodRating, 3, "low", {
    excellent: "Product schema with full details — AI can reference your products precisely.",
    good: "Product schema detected.",
    partial: "Incomplete Product schema found.",
    weak: "Minimal Product schema.",
    missing: "No Product schema. If you offer purchasable items or SaaS plans, add Product JSON-LD.",
    default: "Product schema needs improvement.",
  }));

  const vidBlock = blocks.find(b => b.toLowerCase().includes('"videoobject"'));
  const vidRating: Rating = !vidBlock ? "missing" : "good";
  add(makeCheck("video", "VideoObject Schema", vidRating, 2, "low", {
    excellent: "VideoObject schema with name, description, and thumbnailUrl — video content is AI-discoverable.",
    good: "VideoObject schema detected.",
    partial: "Incomplete VideoObject schema.",
    weak: "Minimal VideoObject schema.",
    missing: "No VideoObject schema. If you publish video content, add VideoObject JSON-LD for AI discoverability.",
    default: "VideoObject schema needs improvement.",
  }));

  return { score: Math.min(100, Math.round(rawTotal)), recs, subChecks: checks };
}

// ===========================================================================
// CATEGORY 2 — AI Citability  (weight = 25 pts)
// ===========================================================================
function scoreAiCitability(
  html: string,
  llmsTxt: string | null,
  robotsTxt: string | null,
  blocks: string[],
): ScoreResult {
  const plainText = stripHtml(html);
  const checks: SubCheck[] = [];
  const recs: string[] = [];
  let rawTotal = 0;

  function add(c: CheckResult): void {
    checks.push(c.score);
    rawTotal += c.pts;
    if (c.score.status === "fail") recs.push(c.score.note);
  }

  const llmsLen = llmsTxt?.length ?? 0;
  const llmsHasUrls = llmsTxt ? /https?:\/\//i.test(llmsTxt) : false;
  const llmsRating: Rating = !llmsTxt ? "missing"
    : llmsLen > 400 && llmsHasUrls ? "excellent"
      : llmsLen > 100 && llmsHasUrls ? "good"
        : llmsLen > 50 ? "partial"
          : "weak";
  add(makeCheck("llms", "llms.txt File", llmsRating, 20, "high", {
    excellent: "llms.txt with site description and key page URLs detected — optimal LLM crawler guidance.",
    good: "llms.txt found with URLs but needs more content depth (target 400+ chars).",
    partial: "llms.txt exists but lacks URL references — add key page links for LLM crawlers.",
    weak: "Very minimal llms.txt — expand with company description and all key page URLs.",
    missing: "No llms.txt detected. Create /llms.txt with a company summary and key page URLs — this is the emerging standard for AI crawler guidance and directly impacts citability.",
    default: "llms.txt needs improvement.",
  }));

  const hasFaqSchema = hasSchemaType(blocks, "FAQPage");
  const hasFaqContent = /\bfaq\b|\bfrequently asked\b/i.test(plainText)
    || /<(details|summary|dl)/i.test(html);
  const faqQCount = (() => {
    const node = findSchemaNode(blocks, "FAQPage");
    if (!node) return 0;
    const me = node.mainEntity;
    return Array.isArray(me) ? me.length : 0;
  })();
  const faqRating: Rating = hasFaqSchema && faqQCount >= 5 ? "excellent"
    : hasFaqSchema && faqQCount >= 2 ? "good"
      : hasFaqContent && hasFaqSchema ? "partial"
        : hasFaqContent ? "weak"
          : "missing";
  add(makeCheck("faqcontent", "AI-readable FAQ Content", faqRating, 18, "high", {
    excellent: `FAQ content with ${faqQCount} structured Q&A pairs and FAQPage schema — top AI extraction signal.`,
    good: "FAQ content and schema present — add 3+ more question/answer pairs to reach full marks.",
    partial: "FAQ content exists but schema markup is incomplete or Q&A count is low.",
    weak: "FAQ-style content detected without proper schema markup — AI cannot reliably extract answers.",
    missing: "No FAQ content or schema detected. Q&A format is the most extractable content type for AI. Add a FAQ section with FAQPage JSON-LD and 5+ questions.",
    default: "FAQ content and schema need improvement.",
  }));

  const hasCanonical = /<link[^>]+rel=["']canonical["']/i.test(html);
  const canonicalHasAbsoluteUrl = /<link[^>]+rel=["']canonical["'][^>]+href=["']https?:\/\//i.test(html);
  const canonicalRating: Rating = hasCanonical && canonicalHasAbsoluteUrl ? "excellent"
    : hasCanonical ? "good"
      : "missing";
  add(makeCheck("canonical", "Canonical URL Declaration", canonicalRating, 10, "high", {
    excellent: "Absolute canonical URL tag detected — URL authority consolidated for AI indexing.",
    good: "Canonical tag present but may use relative URL — use absolute canonical URLs.",
    partial: "Partial canonical implementation detected.",
    weak: "Weak canonical signals.",
    missing: "No canonical tag detected. Add self-referencing canonical link tags to every page to prevent duplicate content issues and consolidate AI indexing signals.",
    default: "Canonical implementation needs improvement.",
  }));

  const hasRobots = !!robotsTxt && robotsTxt.length > 10;
  const hasAiCrawlers = robotsTxt ? /GPTBot|ClaudeBot|PerplexityBot|anthropic/i.test(robotsTxt) : false;
  const hasSitemap = robotsTxt ? /sitemap:/i.test(robotsTxt) : false;
  const blocksAll = robotsTxt ? /disallow:\s*\//i.test(robotsTxt) : false;
  const robotsRating: Rating = hasRobots && hasAiCrawlers && hasSitemap && !blocksAll ? "excellent"
    : hasRobots && (hasAiCrawlers || hasSitemap) ? "good"
      : hasRobots ? "partial"
        : "missing";
  add(makeCheck("robots", "robots.txt AI Crawler Config", robotsRating, 10, "high", {
    excellent: "robots.txt explicitly configures AI crawlers (GPTBot, ClaudeBot) and references sitemap — optimal AI indexing.",
    good: "robots.txt present with partial AI crawler config — add explicit GPTBot/ClaudeBot rules and sitemap reference.",
    partial: "Basic robots.txt found but missing AI crawler rules and sitemap declaration.",
    weak: "Minimal robots.txt detected.",
    missing: "No robots.txt detected. Create robots.txt with User-agent rules for GPTBot, ClaudeBot, PerplexityBot and a sitemap declaration.",
    default: "robots.txt needs AI crawler configuration.",
  }));

  const statsMatches = (plainText.match(/\d+(\.\d+)?%|\$[\d,]+|\d+\s*(clients|projects|years|users|cases|hours)/gi) || []).length;
  const statsRating: Rating = statsMatches >= 5 ? "excellent"
    : statsMatches >= 3 ? "good"
      : statsMatches >= 1 ? "partial"
        : "missing";
  add(makeCheck("stats", "Extractable Facts & Statistics", statsRating, 10, "medium", {
    excellent: `${statsMatches} specific statistics or data points detected — strong citability signal.`,
    good: `${statsMatches} data points found — add 2+ more specific facts/percentages for full marks.`,
    partial: `Only ${statsMatches} measurable facts found — AI systems prefer pages with 5+ specific, verifiable statistics.`,
    weak: "Minimal quantifiable facts — add specific numbers, percentages, and measurable outcomes.",
    missing: "No specific statistics or quantifiable facts found. AI systems strongly prefer citing pages with verifiable data. Add percentages, client counts, project numbers, or time metrics.",
    default: "Add more specific, citable statistics.",
  }));

  const semanticTags = (html.match(/<(article|section|main|aside|nav|header|footer|figure|figcaption|mark|blockquote|dl|dt|dd)/gi) || []).length;
  const semanticRating: Rating = semanticTags >= 8 ? "excellent"
    : semanticTags >= 4 ? "good"
      : semanticTags >= 2 ? "partial"
        : semanticTags >= 1 ? "weak"
          : "missing";
  add(makeCheck("semantic", "Semantic HTML Structure", semanticRating, 10, "medium", {
    excellent: "Rich semantic HTML with article, section, aside, main, and landmark elements — excellent AI content parsing.",
    good: "Good semantic HTML usage — add more landmark elements (aside, figure, blockquote) for full marks.",
    partial: "Some semantic HTML detected but limited — use article, section, main, aside, and figure consistently.",
    weak: "Minimal semantic HTML — switch from div-heavy layout to semantic elements.",
    missing: "No semantic HTML elements detected. Replace divs with semantic HTML (article, section, main, aside) throughout the site.",
    default: "Improve semantic HTML structure.",
  }));

  const substantiveParagraphs = (html.match(/<p[^>]*>[^<]{120,}<\/p>/gi) || []).length;
  const citationRating: Rating = substantiveParagraphs >= 6 ? "excellent"
    : substantiveParagraphs >= 3 ? "good"
      : substantiveParagraphs >= 1 ? "partial"
        : "missing";
  add(makeCheck("citation", "Citation-ready Paragraphs", citationRating, 8, "medium", {
    excellent: `${substantiveParagraphs} substantive paragraphs — content is quotable and citation-ready.`,
    good: `${substantiveParagraphs} substantive paragraphs found — add 3+ more for full citation readiness.`,
    partial: `Only ${substantiveParagraphs} citation-ready paragraphs — expand content with self-contained, citable blocks.`,
    weak: "Very few substantive paragraphs — AI systems cannot extract meaningful quotes.",
    missing: "No citation-ready content found. Write substantive paragraphs (120+ chars) that are independently understandable when quoted out of context.",
    default: "Add more substantive, independently quotable paragraphs.",
  }));

  const hasSameAs = blocks.some(b => b.includes('"sameAs"'));
  const hasMentionsOrg = /Organization|company|business|firm|agency|startup/i.test(plainText);
  const entityRating: Rating = hasSameAs && hasMentionsOrg ? "excellent"
    : hasSameAs ? "good"
      : hasMentionsOrg ? "partial"
        : "weak";
  add(makeCheck("entity", "Entity-rich Content", entityRating, 7, "medium", {
    excellent: "Entity-rich content with sameAs links and organization mentions — AI can verify and contextualize your business.",
    good: "sameAs entity links detected — add organization context in content for full entity richness.",
    partial: "Organization entity mentioned in content but no sameAs verification links in schema.",
    weak: "Weak entity signals — entity content and sameAs links are both missing.",
    missing: "No entity signals detected. Add sameAs links in Organization schema and mention your business entity type in content.",
    default: "Improve entity richness in content and schema.",
  }));

  const hasNoindex = /<meta[^>]+content=["'][^"']*noindex/i.test(html);
  const hasNofollow = /<meta[^>]+content=["'][^"']*nofollow/i.test(html);
  const crawlRating: Rating = !hasNoindex && !hasNofollow ? "excellent"
    : hasNoindex ? "missing"
      : "partial";
  add(makeCheck("crawl", "Crawlability", crawlRating, 4, "high", {
    excellent: "Page is fully crawlable — no noindex or nofollow restrictions detected.",
    good: "Page appears crawlable.",
    partial: "Some crawl restrictions detected — review nofollow tags.",
    weak: "Potential crawlability issues.",
    missing: "Noindex tag detected — this page is blocked from AI crawler indexing. Remove noindex unless intentional.",
    default: "Review crawlability settings.",
  }));

  const tableCount = (html.match(/<table/gi) || []).length;
  const dlCount = (html.match(/<dl/gi) || []).length;
  const machineRating: Rating = (tableCount + dlCount) >= 2 ? "excellent"
    : (tableCount + dlCount) >= 1 ? "good"
      : /<ul[^>]*>[\s\S]{100,}/i.test(html) ? "partial"
        : "weak";
  add(makeCheck("machine", "Machine-readable Content Formats", machineRating, 3, "low", {
    excellent: "Tables and definition lists detected — structured data is easily extractable by AI.",
    good: "Some structured content formats detected — add tables or definition lists for richer extraction.",
    partial: "List-based content present but no tables or definition lists — consider using more structured formats.",
    weak: "Limited machine-readable content formats — add tables, definition lists for AI extraction.",
    missing: "No machine-readable structured formats.",
    default: "Add tables or definition lists for machine-readable content.",
  }));

  return { score: Math.min(100, Math.round(rawTotal)), recs, subChecks: checks };
}

// ===========================================================================
// CATEGORY 3 — E-E-A-T Signals  (weight = 20 pts)
// ===========================================================================
function scoreEeat(html: string, plainText: string): ScoreResult {
  const checks: SubCheck[] = [];
  const recs: string[] = [];
  let rawTotal = 0;

  function add(c: CheckResult): void {
    checks.push(c.score);
    rawTotal += c.pts;
    if (c.score.status === "fail") recs.push(c.score.note);
  }

  const hasCaseStudy = /case\s*stud|success story|portfolio|project outcome|client result/i.test(plainText);
  const hasDetailedCase = hasCaseStudy && /result|outcome|improvement|increase|reduce|measur/i.test(plainText);
  const caseRating: Rating = hasDetailedCase ? "good" : hasCaseStudy ? "partial" : "missing";
  add(makeCheck("cases", "Case Studies / Portfolio", caseRating, 20, "high", {
    excellent: "Detailed case studies with measurable outcomes detected — strong E-E-A-T signal.",
    good: "Case study content detected with results — ensure each study includes specific metrics and client confirmation.",
    partial: "Case study content mentioned but without measurable outcomes or verifiable results.",
    weak: "Portfolio mentioned but lacks substance.",
    missing: "No case studies or portfolio content detected. Case studies with measurable results are the strongest E-E-A-T signal for AI. Publish 2-3 detailed case studies immediately.",
    default: "Add detailed case studies with specific, measurable outcomes.",
  }));

  const hasAuthorName = /by [A-Z][a-z]+ [A-Z][a-z]+|written by|author:/i.test(html);
  const hasAuthorCredentials = /\b(CEO|CTO|founder|director|manager|consultant|specialist|expert)\b/i.test(plainText);
  const hasAuthorLinks = /\/author\/|\/team\/|\/about\//i.test(html);
  const authorRating: Rating = hasAuthorName && hasAuthorCredentials && hasAuthorLinks ? "excellent"
    : hasAuthorName && hasAuthorCredentials ? "good"
      : hasAuthorName ? "partial"
        : "missing";
  add(makeCheck("author", "Author Profiles", authorRating, 18, "high", {
    excellent: "Named authors with credentials and profile links detected — strong expertise signal for AI.",
    good: "Author name and credentials present — add linked author profile pages for full E-E-A-T compliance.",
    partial: "Author names mentioned but without credentials or profile pages — AI cannot verify expertise.",
    weak: "Weak author signals detected.",
    missing: "No author information detected. Named authors with verifiable credentials are essential for E-E-A-T. Add author bylines with roles and linked profile pages.",
    default: "Add named authors with credentials and dedicated profile pages.",
  }));

  const hasTestimonial = /testimonial|review|said|what.*client|what.*customer/i.test(html);
  const hasNamedTestimonial = /["'][\s\S]{30,}["'][\s\S]{0,80}(—|-|by|,)\s*[A-Z][a-z]+ [A-Z]/i.test(html);
  const testimonialRating: Rating = hasNamedTestimonial ? "good"
    : hasTestimonial ? "partial"
      : "missing";
  add(makeCheck("testimonials", "Named Testimonials & Social Proof", testimonialRating, 15, "high", {
    excellent: "Named client testimonials with specific results detected — strong social proof for AI citation.",
    good: "Named testimonials present — add specific outcomes or role/company attribution for full marks.",
    partial: "Testimonial section exists but lacks named attribution or specific results.",
    weak: "Generic testimonial-style content without names or specifics.",
    missing: "No testimonials detected. Named client testimonials with specific results significantly improve E-E-A-T credibility for AI systems.",
    default: "Add named testimonials with specific outcomes.",
  }));

  const hasTeamContent = /\bteam\b|\babout us\b|\bour story\b|\bleadership\b|\bfounders?\b/i.test(plainText);
  const hasTeamDetail = hasTeamContent && /\byears?\b|\bexperienc|\bexpertise|\bspeciali/i.test(plainText);
  const teamRating: Rating = hasTeamDetail ? "good" : hasTeamContent ? "partial" : "missing";
  add(makeCheck("team", "Team / About Page", teamRating, 12, "high", {
    excellent: "Detailed team and about content with expertise and experience — full entity verification possible.",
    good: "Team/About content with some experience details — add specific expertise, years, and credentials.",
    partial: "Team or About page mentioned but lacks detail — add named members, roles, and experience.",
    weak: "Minimal team or about information.",
    missing: "No team or about content detected. A detailed About/Team page with real people and verifiable credentials is critical for E-E-A-T compliance.",
    default: "Expand Team/About content with specific people, roles, and credentials.",
  }));

  const hasEmail = /[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}/i.test(plainText);
  const hasPhone = /\+?[\d\s\-()]{10,}/i.test(plainText);
  const hasAddress = /\b(street|avenue|road|blvd|suite|floor|building|city|country|region)\b/i.test(plainText);
  const contactScore = [hasEmail, hasPhone, hasAddress].filter(Boolean).length;
  const contactRating: Rating = contactScore >= 3 ? "excellent"
    : contactScore >= 2 ? "good"
      : contactScore >= 1 ? "partial"
        : "missing";
  add(makeCheck("contact", "Contact Transparency", contactRating, 10, "medium", {
    excellent: "Email, phone, and address all present — business identity is fully verifiable.",
    good: "Email and phone (or address) found — add all three for complete business verification.",
    partial: "Only one contact method found — add email, phone, and business address.",
    weak: "Very limited contact information.",
    missing: "No clear contact information detected. Business legitimacy depends on verifiable contact details — add email, phone, and address.",
    default: "Add complete contact information (email, phone, address).",
  }));

  const hasCert = /certif|accredit|award|partner|certified|ISO|Microsoft partner|Google partner/i.test(plainText);
  const certRating: Rating = hasCert ? "good" : "missing";
  add(makeCheck("certifications", "Certifications & Awards", certRating, 8, "medium", {
    excellent: "Named certifications with verified partner status — strong authority signal.",
    good: "Certifications or awards mentioned — ensure they are specific and verifiable.",
    partial: "Certification-style language without specifics.",
    weak: "Weak certification signals.",
    missing: "No certifications or awards detected. List any industry certifications, partner programs, or awards with specific details.",
    default: "Add specific, verifiable certifications and awards.",
  }));

  const hasYearsExp = /\d+\+?\s*(years?|yr)(\s*of)?\s*(experience|expertise|operation)/i.test(plainText);
  const hasProjectCount = /\d+\+?\s*(projects?|clients?|companies|businesses)/i.test(plainText);
  const expRating: Rating = hasYearsExp && hasProjectCount ? "good"
    : hasYearsExp || hasProjectCount ? "partial"
      : "missing";
  add(makeCheck("experience", "Quantified Experience Signals", expRating, 7, "medium", {
    excellent: "Specific years of experience and project/client counts — credibility claims are quantified.",
    good: "Some quantified experience signals — add both years of experience and project/client count.",
    partial: "One type of experience signal found — add specific numbers for both experience and deliverables.",
    weak: "Vague experience claims without numbers.",
    missing: "No quantified experience signals. Add specific claims like '7+ years of experience' and '50+ projects delivered' with evidence.",
    default: "Quantify experience with specific numbers.",
  }));

  const hasPrivacy = /privacy\s*policy|gdpr|data protection/i.test(html);
  const hasTerms = /terms\s*(of\s*)?(service|use|conditions)|legal/i.test(html);
  const legalRating: Rating = hasPrivacy && hasTerms ? "excellent"
    : hasPrivacy || hasTerms ? "good"
      : "missing";
  add(makeCheck("privacy", "Privacy Policy & Legal Pages", legalRating, 5, "low", {
    excellent: "Privacy Policy and Terms of Service both detected — legal compliance is established.",
    good: "One legal page found — add both Privacy Policy and Terms of Service.",
    partial: "Legal page content referenced but may not be a dedicated page.",
    weak: "Minimal legal signals.",
    missing: "No Privacy Policy or Terms of Service detected. These are trust signals that AI systems consider when evaluating business legitimacy.",
    default: "Add Privacy Policy and Terms of Service pages.",
  }));

  const hasTrustBadge = /trust|secure|ssl|verified|guaranteed|satisfaction/i.test(plainText);
  const trustRating: Rating = hasTrustBadge ? "partial" : "missing";
  add(makeCheck("trust", "Trust Indicators", trustRating, 5, "low", {
    excellent: "Multiple trust signals including verified badges and guarantees — strong trust foundation.",
    good: "Trust indicators present — add verified badges or money-back guarantees.",
    partial: "Some trust language detected — add visual trust badges and security indicators.",
    weak: "Minimal trust signals.",
    missing: "No trust indicators detected. Add security badges, satisfaction guarantees, or verified seals.",
    default: "Add trust indicators and security badges.",
  }));

  return { score: Math.min(100, Math.round(rawTotal)), recs, subChecks: checks };
}

// ===========================================================================
// CATEGORY 4 — Technical AI Readiness  (weight = 10 pts)
// ===========================================================================
function scoreTechnical(html: string, robotsTxt: string | null): ScoreResult {
  const checks: SubCheck[] = [];
  const recs: string[] = [];
  let rawTotal = 0;

  function add(c: CheckResult): void {
    checks.push(c.score);
    rawTotal += c.pts;
    if (c.score.status === "fail") recs.push(c.score.note);
  }

  const hasViewport = /<meta[^>]+name=["']viewport["']/i.test(html);
  const hasCharset = /<meta[^>]+charset/i.test(html);
  const hasMobileOptimize = /width=device-width/i.test(html);
  const mobileRating: Rating = hasViewport && hasMobileOptimize && hasCharset ? "excellent"
    : hasViewport && hasMobileOptimize ? "good"
      : hasViewport ? "partial"
        : "missing";
  add(makeCheck("mobile", "Mobile & Responsive Configuration", mobileRating, 25, "high", {
    excellent: "Viewport meta tag with device-width and charset — fully mobile-optimized.",
    good: "Viewport tag present — add charset declaration for full mobile compliance.",
    partial: "Viewport tag found but may not be correctly configured.",
    weak: "Minimal mobile configuration.",
    missing: "No viewport meta tag — site may not be mobile-optimized, which impacts AI crawler rendering.",
    default: "Add proper viewport and mobile meta tags.",
  }));

  const hasOgTitle = /<meta[^>]+property=["']og:title["']/i.test(html);
  const hasOgDesc = /<meta[^>]+property=["']og:description["']/i.test(html);
  const hasOgImage = /<meta[^>]+property=["']og:image["']/i.test(html);
  const ogScore = [hasOgTitle, hasOgDesc, hasOgImage].filter(Boolean).length;
  const ogRating: Rating = ogScore === 3 ? "excellent"
    : ogScore === 2 ? "good"
      : ogScore === 1 ? "partial"
        : "missing";
  add(makeCheck("opengraph", "Open Graph / Social Meta Tags", ogRating, 20, "medium", {
    excellent: "Full Open Graph implementation (title, description, image) — content is shareable and AI-readable.",
    good: "Partial Open Graph — add og:image for full social sharing and AI knowledge extraction.",
    partial: "Minimal Open Graph implementation — add og:title, og:description, and og:image.",
    weak: "Very few Open Graph tags.",
    missing: "No Open Graph tags detected. Add og:title, og:description, and og:image to enable rich sharing and AI content extraction.",
    default: "Add complete Open Graph meta tags.",
  }));

  const hasTitle = /<title>[^<]{10,}<\/title>/i.test(html);
  const hasMetaDesc = /<meta[^>]+name=["']description["'][^>]+content=["'][^"']{50,}/i.test(html);
  const hasH1 = /<h1[^>]*>[^<]{5,}<\/h1>/i.test(html);
  const metaRating: Rating = hasTitle && hasMetaDesc && hasH1 ? "excellent"
    : hasTitle && hasMetaDesc ? "good"
      : hasTitle || hasMetaDesc ? "partial"
        : "missing";
  add(makeCheck("meta", "Title & Meta Description", metaRating, 20, "high", {
    excellent: "Title, meta description, and H1 all present and substantive — strong semantic signals.",
    good: "Title and meta description found — add a descriptive H1 heading for full semantic clarity.",
    partial: "Only title or meta description found — add both with descriptive, keyword-rich content.",
    weak: "Minimal title/meta implementation.",
    missing: "No title or meta description detected. These are fundamental AI indexing signals — add immediately.",
    default: "Add title, meta description, and H1 heading.",
  }));

  const hasSitemapRef = robotsTxt ? /sitemap:/i.test(robotsTxt) : false;
  const hasSitemapInHtml = /sitemap\.xml/i.test(html);
  const sitemapRating: Rating = hasSitemapRef ? "excellent"
    : hasSitemapInHtml ? "good"
      : "missing";
  add(makeCheck("sitemap", "XML Sitemap", sitemapRating, 15, "medium", {
    excellent: "Sitemap referenced in robots.txt — AI crawlers can discover all pages.",
    good: "Sitemap URL found in HTML — add Sitemap declaration to robots.txt for AI crawler priority.",
    partial: "Partial sitemap implementation.",
    weak: "Minimal sitemap signals.",
    missing: "No sitemap reference detected. Create an XML sitemap and reference it in robots.txt for comprehensive AI crawler coverage.",
    default: "Create and reference XML sitemap in robots.txt.",
  }));

  const hasHttps = true; // We normalize to https
  const httpsRating: Rating = hasHttps ? "excellent" : "missing";
  add(makeCheck("https", "HTTPS Security", httpsRating, 10, "high", {
    excellent: "Site uses HTTPS — secure connection establishes basic trust for AI systems.",
    good: "HTTPS detected.",
    partial: "Partial HTTPS implementation.",
    weak: "HTTP detected — upgrade to HTTPS immediately.",
    missing: "HTTP only — AI systems and search engines strongly prefer HTTPS. Upgrade immediately.",
    default: "Enable HTTPS.",
  }));

  const hasHreflang = /<link[^>]+hreflang/i.test(html);
  const hreflangRating: Rating = hasHreflang ? "good" : "partial";
  add(makeCheck("hreflang", "Hreflang / Internationalization", hreflangRating, 5, "low", {
    excellent: "Hreflang tags with multiple locales — international AI indexing optimized.",
    good: "Hreflang tags detected — international content is properly attributed.",
    partial: "No hreflang tags — acceptable for single-language sites.",
    weak: "Missing hreflang for multi-language content.",
    missing: "No hreflang implementation — if serving multiple languages, add hreflang tags.",
    default: "Consider adding hreflang tags for international content.",
  }));

  const hasWebManifest = /manifest\.json/i.test(html);
  const manifestRating: Rating = hasWebManifest ? "good" : "partial";
  add(makeCheck("manifest", "Web App Manifest / PWA Signals", manifestRating, 5, "low", {
    excellent: "Web manifest detected — PWA signals present.",
    good: "Web manifest found — progressive web app capability established.",
    partial: "No web manifest — acceptable for content sites.",
    weak: "Missing web manifest.",
    missing: "No web manifest detected.",
    default: "Consider adding a web app manifest.",
  }));

  return { score: Math.min(100, Math.round(rawTotal)), recs, subChecks: checks };
}

// ===========================================================================
// CATEGORY 5 — Content Quality  (weight = 10 pts)
// ===========================================================================
function scoreContentQuality(html: string, plainText: string): ScoreResult {
  const checks: SubCheck[] = [];
  const recs: string[] = [];
  let rawTotal = 0;

  function add(c: CheckResult): void {
    checks.push(c.score);
    rawTotal += c.pts;
    if (c.score.status === "fail") recs.push(c.score.note);
  }

  const wordCount = plainText.split(/\s+/).filter(w => w.length > 2).length;
  const depthRating: Rating = wordCount >= 1500 ? "excellent"
    : wordCount >= 800 ? "good"
      : wordCount >= 300 ? "partial"
        : wordCount >= 100 ? "weak"
          : "missing";
  add(makeCheck("depth", "Content Depth & Word Count", depthRating, 25, "high", {
    excellent: `~${wordCount} words — substantial content depth supports AI comprehension and citation.`,
    good: `~${wordCount} words — reasonable depth; aim for 1500+ for comprehensive AI understanding.`,
    partial: `~${wordCount} words — thin content limits AI's ability to extract and cite detailed information.`,
    weak: `~${wordCount} words — very thin content. AI systems struggle to extract meaningful information.`,
    missing: "Almost no extractable text — page may be JavaScript-rendered or mostly images.",
    default: "Increase content depth for better AI comprehension.",
  }));

  const h2Count = (html.match(/<h2/gi) || []).length;
  const h3Count = (html.match(/<h3/gi) || []).length;
  const headingRating: Rating = h2Count >= 3 && h3Count >= 2 ? "excellent"
    : h2Count >= 2 ? "good"
      : h2Count >= 1 ? "partial"
        : "missing";
  add(makeCheck("headings", "Heading Hierarchy & Structure", headingRating, 20, "medium", {
    excellent: "Strong heading hierarchy with H2 and H3 structure — AI can extract topic clusters.",
    good: "Good heading structure — add H3 subheadings for finer content organization.",
    partial: "Minimal heading structure — add H2 and H3 headings to organize content for AI parsing.",
    weak: "Very few headings detected.",
    missing: "No heading structure detected. Add H2 and H3 headings to organize content for AI topic extraction.",
    default: "Add proper heading hierarchy with H2 and H3 tags.",
  }));

  const listCount = (html.match(/<(ul|ol)/gi) || []).length;
  const listRating: Rating = listCount >= 3 ? "excellent"
    : listCount >= 2 ? "good"
      : listCount >= 1 ? "partial"
        : "missing";
  add(makeCheck("lists", "Lists & Structured Content", listRating, 15, "medium", {
    excellent: "Multiple lists and structured content formats — AI can extract itemized information.",
    good: "Lists present — add more for comprehensive feature/benefit extraction.",
    partial: "Some list content detected — expand with more bullet and numbered lists.",
    weak: "Minimal list content.",
    missing: "No lists detected. Use bullet points and numbered lists to make information extractable for AI.",
    default: "Add lists to organize and extract content points.",
  }));

  const hasVideo = /<(video|iframe)[^>]*(youtube|vimeo|wistia)/i.test(html);
  const hasImage = (html.match(/<img/gi) || []).length >= 3;
  const mediaRating: Rating = hasVideo && hasImage ? "excellent"
    : hasVideo || hasImage ? "good"
      : "partial";
  add(makeCheck("media", "Multimedia Content", mediaRating, 10, "low", {
    excellent: "Video and image content detected — rich media supports AI content understanding.",
    good: "Some multimedia content found — add both video and images for rich content signals.",
    partial: "Minimal multimedia — consider adding images and video content.",
    weak: "Very little multimedia content.",
    missing: "No multimedia content detected.",
    default: "Add images and video content to enrich AI understanding.",
  }));

  const hasInternalLinks = (html.match(/<a[^>]+href=["']\/[^"']/gi) || []).length >= 3;
  const hasExternalLinks = (html.match(/<a[^>]+href=["']https?:\/\/(?!(?:www\.)?[^"']*)[^"']/gi) || []).length >= 1;
  const linkRating: Rating = hasInternalLinks && hasExternalLinks ? "excellent"
    : hasInternalLinks ? "good"
      : "partial";
  add(makeCheck("links", "Internal & External Linking", linkRating, 15, "medium", {
    excellent: "Strong internal and external linking — AI can traverse your content graph and verify claims.",
    good: "Good internal linking — add authoritative external links for source verification.",
    partial: "Limited linking structure — improve internal navigation and add external citations.",
    weak: "Minimal link structure.",
    missing: "No internal or external links detected.",
    default: "Add internal links and authoritative external citations.",
  }));

  const hasFreshDate = /<time[^>]+datetime|datePublished|dateModified/i.test(html);
  const freshnessRating: Rating = hasFreshDate ? "good" : "partial";
  add(makeCheck("freshness", "Content Freshness Signals", freshnessRating, 15, "medium", {
    excellent: "Publication and modification dates with structured markup — freshness is AI-verifiable.",
    good: "Date markup detected — add both datePublished and dateModified for full freshness signaling.",
    partial: "No date markup found — add <time> or schema datePublished/dateModified.",
    weak: "Minimal freshness signals.",
    missing: "No content freshness signals — AI may consider content stale.",
    default: "Add publication and modification date markup.",
  }));

  return { score: Math.min(100, Math.round(rawTotal)), recs, subChecks: checks };
}

// ===========================================================================
// CATEGORY 6 — Brand Authority  (weight = 5 pts)
// ===========================================================================
function scoreBrandAuthority(html: string, blocks: string[]): ScoreResult {
  const checks: SubCheck[] = [];
  const recs: string[] = [];
  let rawTotal = 0;

  function add(c: CheckResult): void {
    checks.push(c.score);
    rawTotal += c.pts;
    if (c.score.status === "fail") recs.push(c.score.note);
  }

  const sameAsBlock = blocks.find(b => b.includes('"sameAs"'));
  const sameAsCount = sameAsBlock
    ? (sameAsBlock.match(/https?:\/\//gi) || []).length
    : 0;
  const kgRating: Rating = sameAsCount >= 3 ? "excellent"
    : sameAsCount >= 1 ? "good"
      : "missing";
  add(makeCheck("sameas", "Knowledge Graph / sameAs Links", kgRating, 30, "high", {
    excellent: `${sameAsCount} sameAs links detected — strong Knowledge Graph signals for AI entity verification.`,
    good: `${sameAsCount} sameAs link(s) found — add 2+ more (LinkedIn, Wikidata, Crunchbase, directories) for full Knowledge Graph presence.`,
    partial: "Partial sameAs implementation.",
    weak: "Minimal sameAs links.",
    missing: "No sameAs links detected. Add sameAs in Organization schema pointing to LinkedIn, Wikidata, Crunchbase — these enable AI to verify and contextualize your brand.",
    default: "Add sameAs links to authoritative external profiles.",
  }));

  const hasLinkedIn = /linkedin\.com/i.test(html);
  const linkedInRating: Rating = hasLinkedIn ? "excellent" : "missing";
  add(makeCheck("linkedin", "LinkedIn Company Profile", linkedInRating, 25, "high", {
    excellent: "LinkedIn profile linked — key AI verification source for business legitimacy.",
    good: "LinkedIn reference found.",
    partial: "Partial LinkedIn signal.",
    weak: "Minimal LinkedIn presence.",
    missing: "No LinkedIn profile reference detected. LinkedIn is the primary B2B entity verification source for AI systems — add your company LinkedIn URL to schema and footer.",
    default: "Add LinkedIn company profile link.",
  }));

  const hasSocial = /twitter\.com|x\.com|facebook\.com|instagram\.com|youtube\.com/i.test(html);
  const socialCount = [/twitter|x\.com/i, /facebook/i, /instagram/i, /youtube/i].filter(r => r.test(html)).length;
  const socialRating: Rating = socialCount >= 3 ? "excellent"
    : socialCount >= 2 ? "good"
      : hasSocial ? "partial"
        : "missing";
  add(makeCheck("social", "Social Profile Presence", socialRating, 20, "medium", {
    excellent: "Multiple social profiles linked — broad entity signal across platforms.",
    good: "Some social profiles present — add 3+ platform links for full presence.",
    partial: "Limited social profile linking — add Twitter, Facebook, and YouTube.",
    weak: "Minimal social signals.",
    missing: "No social profile links detected. Social media presence is a key business legitimacy signal for AI.",
    default: "Add social media profile links.",
  }));

  const hasGBP = /google.*business|maps\.google|g\.page/i.test(html);
  const gbpRating: Rating = hasGBP ? "good" : "missing";
  add(makeCheck("gbp", "Google Business Profile", gbpRating, 15, "medium", {
    excellent: "Google Business Profile linked — local entity verification complete.",
    good: "Google Business reference found — ensure profile is fully complete.",
    partial: "Partial Google Business signal.",
    weak: "Minimal GBP signals.",
    missing: "No Google Business Profile reference. GBP is essential for local AI visibility — claim and link your profile.",
    default: "Add Google Business Profile link.",
  }));

  const hasLogoSchema = blocks.some(b => b.includes('"logo"'));
  const logoRating: Rating = hasLogoSchema ? "excellent" : "missing";
  add(makeCheck("logo", "Logo in Structured Data", logoRating, 10, "medium", {
    excellent: "Logo URL in Organization schema — brand is visually identifiable in AI knowledge bases.",
    good: "Logo schema reference detected.",
    partial: "Partial logo schema.",
    weak: "Logo schema missing key details.",
    missing: "No logo in schema detected. Add logo URL to Organization schema for brand recognition in AI knowledge graphs.",
    default: "Add logo URL to Organization schema.",
  }));

  return { score: Math.min(100, Math.round(rawTotal)), recs, subChecks: checks };
}

// ===========================================================================
// Entity detection
// ===========================================================================
function detectEntities(html: string, blocks: string[], hostname: string): EntityCheck[] {
  const brand = hostname.replace(/^www\./, "").split(".")[0];
  const plainText = stripHtml(html);
  const entities: EntityCheck[] = [];

  // Brand name
  const brandMentions = (plainText.match(new RegExp(brand, "gi")) || []).length;
  entities.push({
    entity: brand.charAt(0).toUpperCase() + brand.slice(1),
    type: "Brand",
    detected: brandMentions >= 2,
    confidence: Math.min(95, brandMentions * 15),
    recommendation: brandMentions < 2
      ? `Mention your brand name "${brand}" at least 3 times in the homepage content for entity recognition.`
      : "Brand entity is well-established in content.",
  });

  // Organization schema
  const hasOrg = blocks.some(b => b.toLowerCase().includes('"organization"') || b.toLowerCase().includes('"localbusiness"'));
  entities.push({
    entity: "Organization",
    type: "Schema Entity",
    detected: hasOrg,
    confidence: hasOrg ? 90 : 0,
    recommendation: hasOrg
      ? "Organization schema detected — ensure name, url, logo, and sameAs are all present."
      : "Add Organization or LocalBusiness JSON-LD schema immediately.",
  });

  // Location
  const hasLocation = /\b(city|country|region|state|province|address|located in)\b/i.test(plainText);
  entities.push({
    entity: "Location",
    type: "Place Entity",
    detected: hasLocation,
    confidence: hasLocation ? 65 : 0,
    recommendation: hasLocation
      ? "Location signals detected — add full address in Organization schema for stronger geo-entity verification."
      : "Add location information (city, country) and address to Organization schema.",
  });

  // Service offerings
  const hasServices = /\b(service|solution|offering|product|platform)\b/i.test(plainText);
  entities.push({
    entity: "Services",
    type: "Service Entity",
    detected: hasServices,
    confidence: hasServices ? 70 : 0,
    recommendation: hasServices
      ? "Service entity signals present — add Service JSON-LD schema for each offering."
      : "Add service/offering descriptions and Service schema markup.",
  });

  // People / team
  const hasPerson = blocks.some(b => b.toLowerCase().includes('"person"'));
  entities.push({
    entity: "People / Team",
    type: "Person Entity",
    detected: hasPerson,
    confidence: hasPerson ? 85 : 0,
    recommendation: hasPerson
      ? "Person schema detected — add sameAs links to LinkedIn for stronger author entity verification."
      : "Add Person JSON-LD for founders, authors, and team members with LinkedIn sameAs links.",
  });

  return entities;
}

// ===========================================================================
// Content metrics for the deep-dive section
// ===========================================================================
function buildContentMetrics(html: string, plainText: string, blocks: string[]): ContentMetric[] {
  const wordCount = plainText.split(/\s+/).filter(w => w.length > 2).length;
  const h2Count = (html.match(/<h2/gi) || []).length;
  const statsCount = (plainText.match(/\d+(\.\d+)?%|\$[\d,]+|\d+\s*(clients|projects|years)/gi) || []).length;
  const hasFaqSchema = hasSchemaType(blocks, "FAQPage");
  const substantiveParagraphs = (html.match(/<p[^>]*>[^<]{120,}<\/p>/gi) || []).length;
  const hasOgImage = /<meta[^>]+property=["']og:image["']/i.test(html);

  function s(score: number): ContentMetric["status"] {
    if (score >= 8) return "excellent";
    if (score >= 6) return "good";
    if (score >= 4) return "partial";
    if (score >= 1) return "weak";
    return "missing";
  }

  const depthScore = wordCount >= 1500 ? 10 : wordCount >= 800 ? 7 : wordCount >= 300 ? 4 : wordCount >= 100 ? 2 : 0;
  const structureScore = h2Count >= 4 ? 10 : h2Count >= 2 ? 7 : h2Count >= 1 ? 4 : 0;
  const citabilityScore = substantiveParagraphs >= 6 ? 10 : substantiveParagraphs >= 3 ? 7 : substantiveParagraphs >= 1 ? 4 : 0;
  const statsScore = statsCount >= 5 ? 10 : statsCount >= 3 ? 7 : statsCount >= 1 ? 4 : 0;
  const faqScore = hasFaqSchema ? 9 : /<(details|summary)/i.test(html) ? 5 : 0;
  const visualScore = hasOgImage ? 8 : (html.match(/<img/gi) || []).length >= 3 ? 6 : 3;

  return [
    { key: "depth", label: "Content Depth", score: depthScore, status: s(depthScore), explanation: `~${wordCount} words. ${wordCount >= 800 ? "Good depth for AI comprehension." : "Aim for 800+ words for comprehensive AI understanding."}` },
    { key: "structure", label: "Content Structure", score: structureScore, status: s(structureScore), explanation: `${h2Count} H2 headings. ${h2Count >= 3 ? "Well-structured for AI topic extraction." : "Add H2/H3 headings to organize content into AI-extractable topic clusters."}` },
    { key: "citability", label: "Citation Readiness", score: citabilityScore, status: s(citabilityScore), explanation: `${substantiveParagraphs} substantial paragraphs (120+ chars). ${substantiveParagraphs >= 3 ? "Good citation readiness." : "Write longer, self-contained paragraphs that AI can quote independently."}` },
    { key: "stats", label: "Extractable Statistics", score: statsScore, status: s(statsScore), explanation: `${statsCount} quantifiable data points. ${statsCount >= 3 ? "Good data density." : "Add specific numbers, percentages, and measurable outcomes for AI citation."}` },
    { key: "faq", label: "Q&A / FAQ Content", score: faqScore, status: s(faqScore), explanation: hasFaqSchema ? "FAQPage schema with structured Q&A — top AI extraction signal." : "No FAQ schema. Add FAQPage JSON-LD with 5+ Q&A pairs for AI answer extraction." },
    { key: "visual", label: "Visual Content Signals", score: visualScore, status: s(visualScore), explanation: hasOgImage ? "Open Graph image detected — content is visually shareable for AI." : "Add og:image and multiple content images for richer AI understanding." },
  ];
}

// ===========================================================================
// Issues builder
// ===========================================================================
function buildIssues(
  schemaRes: ScoreResult,
  citRes: ScoreResult,
  eeatRes: ScoreResult,
  techRes: ScoreResult,
): Issue[] {
  const issues: Issue[] = [];
  const allChecks = [
    ...schemaRes.subChecks.map(s => ({ ...s, categoryLabel: "Structured Data" })),
    ...citRes.subChecks.map(s => ({ ...s, categoryLabel: "AI Citability" })),
    ...eeatRes.subChecks.map(s => ({ ...s, categoryLabel: "E-E-A-T Signals" })),
    ...techRes.subChecks.map(s => ({ ...s, categoryLabel: "Technical" })),
  ];

  const issueMap: Record<string, { title: string; whyItMatters: string; recommendedFix: string; expectedScoreIncrease: number; severity: Issue["severity"] }> = {
    org: { severity: "critical", title: "Missing Organization Schema", whyItMatters: "AI systems cannot verify your business identity without Organization schema — you become uncitable.", recommendedFix: "Add Organization JSON-LD with name, url, logo, sameAs (LinkedIn, Wikidata), contactPoint, and address.", expectedScoreIncrease: 12 },
    faq: { severity: "high", title: "Missing or Weak FAQPage Schema", whyItMatters: "FAQ schema is the primary trigger for AI-generated answers. Without it, competitors dominate Q&A responses.", recommendedFix: "Add FAQPage JSON-LD with 5+ question-and-answer pairs covering your core service questions.", expectedScoreIncrease: 8 },
    llms: { severity: "critical", title: "No llms.txt File", whyItMatters: "Without llms.txt, AI crawlers have no structured guidance on what to index, reducing your citation probability.", recommendedFix: "Create /llms.txt with a 200+ word company summary and URLs for all key pages.", expectedScoreIncrease: 10 },
    canonical: { severity: "high", title: "Missing Canonical URL Tags", whyItMatters: "Without canonical tags, AI systems may index duplicate or incorrect page versions, splitting your authority.", recommendedFix: "Add <link rel='canonical' href='https://yourdomain.com/page'> to every page with absolute URLs.", expectedScoreIncrease: 5 },
    cases: { severity: "high", title: "No Case Studies or Portfolio", whyItMatters: "AI systems look for proof of results. Without case studies, your expertise cannot be verified or cited.", recommendedFix: "Publish 2-3 detailed case studies with client names (or anonymized), measurable outcomes, and timelines.", expectedScoreIncrease: 8 },
    author: { severity: "high", title: "No Author Profiles", whyItMatters: "E-E-A-T requires verifiable human expertise. Unattributed content scores lower in AI credibility assessments.", recommendedFix: "Add named author bylines with job titles, short bios, and links to LinkedIn profiles.", expectedScoreIncrease: 7 },
    robots: { severity: "medium", title: "robots.txt Missing AI Crawler Rules", whyItMatters: "Without explicit AI crawler rules, GPTBot and ClaudeBot may not know how to optimally index your content.", recommendedFix: "Add User-agent rules for GPTBot, ClaudeBot, PerplexityBot and a Sitemap: declaration to your robots.txt.", expectedScoreIncrease: 4 },
    meta: { severity: "high", title: "Missing Title or Meta Description", whyItMatters: "Title and meta description are the first signals AI systems use to understand page content and intent.", recommendedFix: "Add a descriptive title (50-60 chars) and meta description (150-160 chars) to every page.", expectedScoreIncrease: 6 },
    person: { severity: "medium", title: "No Person Schema for Team Members", whyItMatters: "Person schema with sameAs links enables AI to verify team expertise and establish E-E-A-T signals.", recommendedFix: "Add Person JSON-LD for founders and key team members with jobTitle, url, and sameAs (LinkedIn).", expectedScoreIncrease: 5 },
    sameas: { severity: "critical", title: "No sameAs / Knowledge Graph Links", whyItMatters: "sameAs links are how AI systems connect your schema to real-world entities in knowledge bases.", recommendedFix: "Add sameAs array to Organization schema with: LinkedIn URL, Wikidata ID, Crunchbase profile, and key directory listings.", expectedScoreIncrease: 9 },
  };

  for (const check of allChecks) {
    if (check.status !== "fail") continue;
    const meta = issueMap[check.key];
    if (!meta) {
      issues.push({
        id: check.key,
        title: `Fix: ${check.label}`,
        severity: check.impact === "high" ? "high" : check.impact === "medium" ? "medium" : "low",
        description: check.note,
        whyItMatters: "This issue reduces your AI visibility and citability score.",
        recommendedFix: check.note,
        expectedScoreIncrease: check.impact === "high" ? 4 : 2,
        category: (check as { categoryLabel?: string }).categoryLabel || "General",
      });
    } else {
      issues.push({
        id: check.key,
        title: meta.title,
        severity: meta.severity,
        description: check.note,
        whyItMatters: meta.whyItMatters,
        recommendedFix: meta.recommendedFix,
        expectedScoreIncrease: meta.expectedScoreIncrease,
        category: (check as { categoryLabel?: string }).categoryLabel || "General",
      });
    }
  }

  return issues.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.severity] - order[b.severity];
  });
}

// ===========================================================================
// Quick wins builder
// ===========================================================================
function buildQuickWins(issues: Issue[], schemaRes: ScoreResult, citRes: ScoreResult): QuickWin[] {
  const wins: QuickWin[] = [];

  const quickWinDefs: Record<string, QuickWin> = {
    llms: { id: "llms", action: "Create /llms.txt with company description + key page URLs", difficulty: "easy", expectedImpact: "high", estimatedTime: "30 min", scoreGain: 8 },
    canonical: { id: "canonical", action: "Add canonical tags to all pages (absolute URLs)", difficulty: "easy", expectedImpact: "high", estimatedTime: "1 hour", scoreGain: 5 },
    org: { id: "org", action: "Add/complete Organization schema (name, logo, sameAs, contactPoint)", difficulty: "medium", expectedImpact: "high", estimatedTime: "2 hours", scoreGain: 10 },
    faq: { id: "faq", action: "Add FAQPage schema with 5+ Q&A pairs to homepage", difficulty: "medium", expectedImpact: "high", estimatedTime: "3 hours", scoreGain: 8 },
    robots: { id: "robots", action: "Add GPTBot/ClaudeBot rules and Sitemap to robots.txt", difficulty: "easy", expectedImpact: "medium", estimatedTime: "20 min", scoreGain: 4 },
    meta: { id: "meta", action: "Write descriptive title and meta description for each page", difficulty: "easy", expectedImpact: "high", estimatedTime: "2 hours", scoreGain: 5 },
    sameas: { id: "sameas", action: "Add sameAs links (LinkedIn, Wikidata, Crunchbase) to Organization schema", difficulty: "easy", expectedImpact: "high", estimatedTime: "1 hour", scoreGain: 7 },
    author: { id: "author", action: "Add author bylines with name, role, and LinkedIn link to all content", difficulty: "medium", expectedImpact: "high", estimatedTime: "4 hours", scoreGain: 6 },
    person: { id: "person", action: "Add Person schema for founders/authors with sameAs LinkedIn", difficulty: "medium", expectedImpact: "medium", estimatedTime: "2 hours", scoreGain: 5 },
    stats: { id: "stats", action: "Add 5+ specific statistics (%, client count, years) to homepage", difficulty: "easy", expectedImpact: "medium", estimatedTime: "1 hour", scoreGain: 4 },
  };

  const failedKeys = new Set([
    ...schemaRes.subChecks.filter(s => s.status === "fail").map(s => s.key),
    ...citRes.subChecks.filter(s => s.status === "fail").map(s => s.key),
    ...issues.map(i => i.id),
  ]);

  for (const key of Object.keys(quickWinDefs)) {
    if (failedKeys.has(key) && wins.length < 8) {
      wins.push(quickWinDefs[key]);
    }
  }

  return wins.sort((a, b) => b.scoreGain - a.scoreGain);
}

// ===========================================================================
// AI platform scores
// ===========================================================================
function buildPlatformScores(overallScore: number, schemaRes: ScoreResult, citRes: ScoreResult, eeatRes: ScoreResult): PlatformScore[] {
  const hasOrg = schemaRes.subChecks.find(s => s.key === "org")?.status !== "fail";
  const hasFaq = schemaRes.subChecks.find(s => s.key === "faq")?.status !== "fail";
  const hasLlms = citRes.subChecks.find(s => s.key === "llms")?.status !== "fail";
  const hasCanonical = citRes.subChecks.find(s => s.key === "canonical")?.status !== "fail";
  const hasEeat = eeatRes.score >= 40;

  function clamp(n: number) { return Math.min(100, Math.max(0, Math.round(n))); }

  return [
    {
      id: "chatgpt",
      name: "ChatGPT / GPT-4",
      score: clamp(overallScore * 0.9 + (hasOrg ? 5 : 0) + (hasFaq ? 5 : 0)),
      status: overallScore >= 65 ? "compatible" : overallScore >= 45 ? "partial" : overallScore >= 25 ? "limited" : "incompatible",
      explanation: overallScore >= 65
        ? "Your site has sufficient structured data for ChatGPT to identify and cite your business in relevant queries."
        : "ChatGPT may reference your business but with limited accuracy. Organization schema and FAQ content are needed for reliable citations.",
      topRecommendation: !hasOrg ? "Add Organization JSON-LD with sameAs links" : !hasFaq ? "Add FAQPage schema with 5+ Q&A pairs" : "Expand content depth and E-E-A-T signals",
    },
    {
      id: "google_ai",
      name: "Google AI Overviews",
      score: clamp(overallScore * 0.95 + (hasCanonical ? 3 : 0) + (hasEeat ? 5 : 0)),
      status: overallScore >= 65 ? "compatible" : overallScore >= 45 ? "partial" : overallScore >= 25 ? "limited" : "incompatible",
      explanation: overallScore >= 65
        ? "Site appears eligible for Google AI Overview inclusion. Strong structured data and E-E-A-T signals are key drivers."
        : "Google AI Overviews requires strong E-E-A-T, structured data, and canonical implementation for reliable inclusion.",
      topRecommendation: !hasCanonical ? "Add canonical tags and ensure proper indexing" : !hasEeat ? "Strengthen E-E-A-T with author profiles and case studies" : "Maintain content freshness and expand FAQ coverage",
    },
    {
      id: "gemini",
      name: "Google Gemini",
      score: clamp(overallScore * 0.85 + (hasOrg ? 8 : 0) + (hasEeat ? 5 : 0)),
      status: overallScore >= 60 ? "compatible" : overallScore >= 40 ? "partial" : overallScore >= 20 ? "limited" : "incompatible",
      explanation: overallScore >= 60
        ? "Gemini can identify and cite your business from structured data and entity signals."
        : "Gemini has limited ability to verify your business. Organization schema with sameAs links and E-E-A-T content are critical.",
      topRecommendation: !hasOrg ? "Add full Organization schema with sameAs verification links" : "Strengthen Knowledge Graph presence with external profile links",
    },
    {
      id: "claude",
      name: "Anthropic Claude",
      score: clamp(overallScore * 0.80 + (hasLlms ? 12 : 0) + (hasFaq ? 5 : 0)),
      status: overallScore >= 60 ? (hasLlms ? "compatible" : "partial") : overallScore >= 40 ? "partial" : overallScore >= 20 ? "limited" : "incompatible",
      explanation: hasLlms
        ? "llms.txt detected — Claude can access structured crawling guidance for your site."
        : overallScore >= 50
          ? "Claude can extract some information but lacks llms.txt guidance and structured citability signals."
          : "Claude has very limited visibility into your business. Create llms.txt and structured FAQ content immediately.",
      topRecommendation: !hasLlms ? "Create /llms.txt — Claude explicitly supports this standard for AI indexing" : !hasFaq ? "Add FAQPage schema for structured answer extraction" : "Expand llms.txt with all key page URLs and service descriptions",
    },
    {
      id: "perplexity",
      name: "Perplexity AI",
      score: clamp(overallScore * 0.88 + (hasOrg ? 5 : 0) + (hasLlms ? 7 : 0)),
      status: overallScore >= 55 ? "compatible" : overallScore >= 35 ? "partial" : overallScore >= 20 ? "limited" : "incompatible",
      explanation: overallScore >= 55
        ? "Perplexity can cite your business from web content and structured signals."
        : "Perplexity relies heavily on web crawling and structured data — strengthen schema and citability for better results.",
      topRecommendation: !hasLlms ? "Create llms.txt to guide Perplexity's crawling" : !hasOrg ? "Add Organization schema for entity verification" : "Add more citation-ready statistics and named testimonials",
    },
  ];
}

// ===========================================================================
// Roadmap builder
// ===========================================================================
function buildRoadmap(issues: Issue[], overallScore: number): RoadmapPhase[] {
  const criticalIssues = issues.filter(i => i.severity === "critical");
  const highIssues = issues.filter(i => i.severity === "high");
  const mediumIssues = issues.filter(i => i.severity === "medium");

  return [
    {
      month: "Month 1",
      title: "Foundation: Schema & Crawlability",
      priority: overallScore < 40 ? "critical" : "high",
      expectedScoreImprovement: 15,
      tasks: [
        "Add/complete Organization JSON-LD with all required properties (name, url, logo, sameAs, contactPoint)",
        "Create /llms.txt with 300+ word company description and URLs for all key pages",
        "Add canonical tags to every page using absolute URLs",
        "Configure robots.txt with GPTBot, ClaudeBot, PerplexityBot rules and Sitemap declaration",
        criticalIssues.length > 0 ? `Fix critical issue: ${criticalIssues[0].title}` : "Audit all pages for missing title and meta description tags",
      ],
    },
    {
      month: "Month 2",
      title: "AI Citability: FAQs & Structured Content",
      priority: "high",
      expectedScoreImprovement: 12,
      tasks: [
        "Add FAQPage JSON-LD with 7+ Q&A pairs to homepage and key service pages",
        "Write 5+ substantive paragraphs (150+ words each) answering common customer questions",
        "Add 5+ specific statistics to homepage (client count, years of experience, project count)",
        highIssues.length > 0 ? `Address high priority: ${highIssues[0].title}` : "Implement BreadcrumbList schema on all interior pages",
        "Add WebSite schema with SearchAction for sitelinks search eligibility",
      ],
    },
    {
      month: "Month 3",
      title: "E-E-A-T: Authority & Expertise",
      priority: "high",
      expectedScoreImprovement: 10,
      tasks: [
        "Add Person JSON-LD for all founders and key team members with LinkedIn sameAs",
        "Publish 2 detailed case studies with measurable outcomes and client attribution",
        "Add named author bylines with job titles and bio links to all content pages",
        "Add Review or AggregateRating schema with verified testimonials",
        "Create dedicated team page with professional photos, credentials, and experience",
      ],
    },
    {
      month: "Month 4",
      title: "Knowledge Graph & Brand Authority",
      priority: "medium",
      expectedScoreImprovement: 8,
      tasks: [
        "Add sameAs links to Organization schema: LinkedIn, Wikidata, Crunchbase, G2, Clutch",
        "Claim and optimize Google Business Profile with complete information",
        "Add company profile to industry directories and citation sites",
        mediumIssues.length > 0 ? `Address: ${mediumIssues[0].title}` : "Submit site to Bing Webmaster Tools for AI Bing chat indexing",
        "Add Open Graph tags (og:title, og:description, og:image) to all pages",
      ],
    },
    {
      month: "Month 5",
      title: "Content Depth & Answer Optimization",
      priority: "medium",
      expectedScoreImprovement: 7,
      tasks: [
        "Expand all key service pages to 1000+ words with structured H2/H3 headings",
        "Add 10+ FAQ questions covering long-tail AI search queries in your niche",
        "Create comparison pages (your service vs alternatives) — high AI citation probability",
        "Add Article schema with datePublished and dateModified to all blog content",
        "Build internal linking structure connecting all service pages to hub pages",
      ],
    },
    {
      month: "Month 6",
      title: "Advanced Optimization & Monitoring",
      priority: "medium",
      expectedScoreImprovement: 5,
      tasks: [
        "Implement content freshness signals — update dateModified on refreshed pages",
        "Add VideoObject schema if publishing video content (YouTube embeds, demos)",
        "Create /llms-full.txt with comprehensive service descriptions and team information",
        "Set up monitoring for AI-generated brand mentions using Perplexity and ChatGPT searches",
        "Quarterly audit cycle: re-run GEO audit and update optimization based on new score",
      ],
    },
  ];
}

const RATING_VALUES: Record<Rating, number> = {
  excellent: 100,
  good: 75,
  partial: 40,
  weak: 20,
  missing: 0,
};

function ratingFromPercent(score: number): Rating {
  if (score >= 85) return "excellent";
  if (score >= 65) return "good";
  if (score >= 35) return "partial";
  if (score > 0) return "weak";
  return "missing";
}

function aggregateScoreResults(results: ScoreResult[]): ScoreResult {
  if (results.length === 0) return { score: 0, recs: [], subChecks: [] };

  const checksByKey = new Map<string, SubCheck[]>();
  for (const result of results) {
    for (const check of result.subChecks) {
      const entries = checksByKey.get(check.key) || [];
      entries.push(check);
      checksByKey.set(check.key, entries);
    }
  }

  const subChecks = [...checksByKey.entries()].map(([key, checks]): SubCheck => {
    const average = checks.reduce((sum, check) => sum + RATING_VALUES[check.rating || (
      check.status === "pass" ? "good" : check.status === "partial" ? "partial" : "missing"
    )], 0) / checks.length;
    const rating = ratingFromPercent(average);
    const passed = checks.filter(check => check.status === "pass").length;
    const partial = checks.filter(check => check.status === "partial").length;
    const failed = checks.filter(check => check.status === "fail").length;
    const impact = checks.some(check => check.impact === "high") ? "high"
      : checks.some(check => check.impact === "medium") ? "medium" : "low";

    return {
      key,
      label: checks[0].label,
      status: rating === "excellent" || rating === "good" ? "pass" : rating === "partial" || rating === "weak" ? "partial" : "fail",
      impact,
      rating,
      averageRating: average,
      sampleCount: checks.length,
      passCount: passed,
      partialCount: partial,
      failCount: failed,
      note: `Across ${checks.length} pages: ${passed} passed, ${partial} were partial, and ${failed} failed.`,
    };
  });

  const score = Math.round(results.reduce((sum, result) => sum + result.score, 0) / results.length);
  const recs = [...new Set(results.flatMap(result => result.recs))];
  return { score, recs, subChecks };
}

function aggregateIssues(pageIssues: { url: string; issues: Issue[] }[]): Issue[] {
  const grouped = new Map<string, Issue & { affectedPages: string[] }>();
  for (const { url, issues } of pageIssues) {
    for (const issue of issues) {
      const key = `${issue.id}:${issue.category}`;
      const current = grouped.get(key);
      if (current) {
        current.affectedPages.push(url);
      } else {
        grouped.set(key, { ...issue, affectedPages: [url] });
      }
    }
  }

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  return [...grouped.values()].sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
}

function aggregateEntities(pageEntities: EntityCheck[][]): EntityCheck[] {
  const grouped = new Map<string, EntityCheck[]>();
  for (const entities of pageEntities) {
    for (const entity of entities) {
      const key = `${entity.type}:${entity.entity}`;
      const entries = grouped.get(key) || [];
      entries.push(entity);
      grouped.set(key, entries);
    }
  }

  return [...grouped.values()].map(entities => {
    const detectedEntities = entities.filter(entity => entity.detected);
    const confidenceEntities = detectedEntities.length > 0 ? detectedEntities : entities;
    return {
      ...entities[0],
      detected: detectedEntities.length > 0,
      confidence: Math.round(confidenceEntities.reduce((sum, entity) => sum + entity.confidence, 0) / confidenceEntities.length),
      recommendation: detectedEntities[0]?.recommendation || entities[0].recommendation,
      sampleCount: entities.length,
      detectedCount: detectedEntities.length,
      confidenceSum: confidenceEntities.reduce((sum, entity) => sum + entity.confidence, 0),
    };
  });
}

function aggregateContentMetrics(pageMetrics: ContentMetric[][]): ContentMetric[] {
  const grouped = new Map<string, ContentMetric[]>();
  for (const metrics of pageMetrics) {
    for (const metric of metrics) {
      const entries = grouped.get(metric.key) || [];
      entries.push(metric);
      grouped.set(metric.key, entries);
    }
  }

  return [...grouped.values()].map(metrics => {
    const score = Math.round(metrics.reduce((sum, metric) => sum + metric.score, 0) / metrics.length);
    const status = score >= 8 ? "excellent" : score >= 6 ? "good" : score >= 4 ? "partial" : score >= 1 ? "weak" : "missing";
    return {
      ...metrics[0],
      score,
      status,
      sampleCount: metrics.length,
      explanation: `Average across ${metrics.length} pages. ${metrics[0].explanation}`,
    };
  });
}

function calculateOverallScore(schemaRes: ScoreResult, citRes: ScoreResult, eeatRes: ScoreResult, techRes: ScoreResult, contentRes: ScoreResult, brandRes: ScoreResult): number {
  return Math.min(100, Math.round(
    schemaRes.score * 0.30 +
    citRes.score * 0.25 +
    eeatRes.score * 0.20 +
    techRes.score * 0.10 +
    contentRes.score * 0.10 +
    brandRes.score * 0.05
  ));
}

// ===========================================================================
// Main POST handler
// ===========================================================================
export async function POST(request: NextRequest) {
  try {
    const body = await request.json() as {
      url?: unknown;
      includeSubdomains?: unknown;
      batchMode?: unknown;
      requestedUrls?: unknown;
    };
    const { url } = body;
    const hasRequestedUrls = body.requestedUrls !== undefined;
    const batchMode = body.batchMode === true || hasRequestedUrls;
    if (hasRequestedUrls && (!Array.isArray(body.requestedUrls) ||
      body.requestedUrls.length > CRAWL_BATCH_SIZE ||
      body.requestedUrls.some(pageUrl => typeof pageUrl !== "string"))) {
      return NextResponse.json({ error: `A crawl batch must contain at most ${CRAWL_BATCH_SIZE} URL strings.` }, { status: 400 });
    }
    const requestedUrls = hasRequestedUrls ? body.requestedUrls as string[] : undefined;

    if (!url || typeof url !== "string") {
      return NextResponse.json({ error: "URL is required" }, { status: 400 });
    }

    const base = normalizeUrl(url);
    let inputUrl: URL;
    try { inputUrl = new URL(base); }
    catch { return NextResponse.json({ error: "Invalid URL" }, { status: 400 }); }

    if (!["http:", "https:"].includes(inputUrl.protocol) || inputUrl.username || inputUrl.password) {
      return NextResponse.json({ error: "Enter a valid public website URL" }, { status: 400 });
    }

    const includeSubdomains = body.includeSubdomains !== false;
    const submittedHost = inputUrl.hostname.toLowerCase().replace(/\.$/, "");
    const rootHost = includeSubdomains ? submittedHost.replace(/^www\./, "") : submittedHost;
    const scope: CrawlScope = {
      rootHost,
      includeSubdomains,
      publicHostCache: new Map(),
    };
    const startUrl = new URL("/", inputUrl.origin).toString();

    if (!(await isSafeTarget(startUrl, scope))) {
      return NextResponse.json(
        { error: "Enter a publicly accessible website URL. Private, local, and out-of-scope hosts cannot be audited." },
        { status: 422 }
      );
    }

    const crawl = await crawlSite(
      startUrl,
      scope,
      requestedUrls,
      batchMode ? CRAWL_BATCH_SIZE : INITIAL_CRAWL_PAGE_LIMIT,
    );
    const crawlBatch: {
      attemptedUrls: string[];
      discoveredUrls: string[];
      failedUrls: string[];
      skippedUrls: string[];
      truncated: boolean;
      maxDiscoveredUrls: number;
      scoreCount?: number;
      categoryScoreSums?: Record<string, number>;
    } = {
      attemptedUrls: crawl.attemptedUrls,
      discoveredUrls: crawl.discoveredUrls,
      failedUrls: crawl.failedUrls,
      skippedUrls: crawl.skippedUrls,
      truncated: crawl.truncated,
      maxDiscoveredUrls: MAX_DISCOVERED_URLS,
    };
    if (crawl.pages.length === 0) {
      if (batchMode) return NextResponse.json({ crawlBatch });
      return NextResponse.json(
        {
          error: crawl.skippedByRobots > 0
            ? "No pages could be audited because robots.txt disallows the discovered URLs."
            : `Unable to analyze pages on ${submittedHost}. The domain may be unavailable or blocking requests.`,
        },
        { status: 422 }
      );
    }

    const pageAudits = crawl.pages.map(page => {
      const files = crawl.hostFiles.get(new URL(page.url).origin);
      const plainText = stripHtml(page.html);
      const blocks = extractJsonLd(page.html);
      const schemaRes = scoreStructuredData(page.html, blocks);
      const citRes = scoreAiCitability(page.html, files?.llmsTxt ?? null, files?.robotsTxt ?? null, blocks);
      const eeatRes = scoreEeat(page.html, plainText);
      const techRes = scoreTechnical(page.html, files?.robotsTxt ?? null);
      const contentRes = scoreContentQuality(page.html, plainText);
      const brandRes = scoreBrandAuthority(page.html, blocks);
      const issues = buildIssues(schemaRes, citRes, eeatRes, techRes);
      const score = calculateOverallScore(schemaRes, citRes, eeatRes, techRes, contentRes, brandRes);

      return {
        url: page.url,
        score,
        schemaRes,
        citRes,
        eeatRes,
        techRes,
        contentRes,
        brandRes,
        issues,
        entities: detectEntities(page.html, blocks, scope.rootHost),
        contentMetrics: buildContentMetrics(page.html, plainText, blocks),
      };
    });
    crawlBatch.scoreCount = pageAudits.length;
    crawlBatch.categoryScoreSums = {
      schema: pageAudits.reduce((sum, page) => sum + page.schemaRes.score, 0),
      citability: pageAudits.reduce((sum, page) => sum + page.citRes.score, 0),
      eeat: pageAudits.reduce((sum, page) => sum + page.eeatRes.score, 0),
      technical: pageAudits.reduce((sum, page) => sum + page.techRes.score, 0),
      content: pageAudits.reduce((sum, page) => sum + page.contentRes.score, 0),
      brand: pageAudits.reduce((sum, page) => sum + page.brandRes.score, 0),
    };

    const schemaRes = aggregateScoreResults(pageAudits.map(page => page.schemaRes));
    const citRes = aggregateScoreResults(pageAudits.map(page => page.citRes));
    const eeatRes = aggregateScoreResults(pageAudits.map(page => page.eeatRes));
    const techRes = aggregateScoreResults(pageAudits.map(page => page.techRes));
    const contentRes = aggregateScoreResults(pageAudits.map(page => page.contentRes));
    const brandRes = aggregateScoreResults(pageAudits.map(page => page.brandRes));
    const overallScore = calculateOverallScore(schemaRes, citRes, eeatRes, techRes, contentRes, brandRes);

    // Citability score — weighted combination of citability category + content + schema
    const citabilityScore = Math.min(100, Math.round(
      citRes.score    * 0.55 +
      schemaRes.score * 0.25 +
      contentRes.score * 0.20
    ));

    // Category details
    const categoryConfigs = [
      { key: "schema",     label: "Structured Data & AI Schema", r: schemaRes,  w: 30 },
      { key: "citability", label: "AI Citability",               r: citRes,     w: 25 },
      { key: "eeat",       label: "E-E-A-T Signals",             r: eeatRes,    w: 20 },
      { key: "technical",  label: "Technical AI Readiness",      r: techRes,    w: 10 },
      { key: "content",    label: "Content Quality",             r: contentRes, w: 10 },
      { key: "brand",      label: "Brand Authority",             r: brandRes,   w:  5 },
    ];

    const categoryDetails: CategoryDetail[] = categoryConfigs.map(c => {
      const weightedScore = Math.round(c.r.score * c.w / 100);
      const failedHigh = c.r.subChecks.filter(s => s.impact === "high" && s.status === "fail");
      const partialHigh = c.r.subChecks.filter(s => s.impact === "high" && s.status === "partial");
      return {
        key: c.key,
        label: c.label,
        weight: c.w,
        rawScore: c.r.score,
        weightedScore,
        maxWeightedScore: c.w,
        status: overallRatingFromScore(c.r.score),
        description: `Average across ${pageAudits.length} analyzed pages; ${c.r.subChecks.length} signals evaluated.`,
        whyLost: failedHigh.length > 0
          ? `Missing: ${failedHigh.map(s => s.label).join(", ")}`
          : partialHigh.length > 0
            ? `Incomplete: ${partialHigh.map(s => s.label).join(", ")}`
            : "Good implementation — focus on excellence-tier optimizations.",
        howToImprove: c.r.recs.slice(0, 3).join(" | ") || "Maintain current implementation and monitor for changes.",
        expectedGain: Math.round((c.w - weightedScore) * 0.6),
        subChecks: c.r.subChecks,
      };
    });

    // Build derived data
    const issues = aggregateIssues(pageAudits.map(page => ({ url: page.url, issues: page.issues })));
    const quickWins = buildQuickWins(issues, schemaRes, citRes);
    const aiPlatforms = buildPlatformScores(overallScore, schemaRes, citRes, eeatRes);
    const entities = aggregateEntities(pageAudits.map(page => page.entities));
    const contentMetrics = aggregateContentMetrics(pageAudits.map(page => page.contentMetrics));
    const roadmap = buildRoadmap(issues, overallScore);

    const allRecs = [...new Set([
      ...schemaRes.recs,
      ...citRes.recs,
      ...eeatRes.recs,
      ...techRes.recs,
      ...contentRes.recs,
      ...brandRes.recs,
    ])].slice(0, 15);

    const criticalIssueCounts = new Map<string, number>();
    for (const page of pageAudits) {
      criticalIssueCounts.set(page.url, page.issues.filter(issue => issue.severity === "critical").length);
    }
    const pagesAnalyzed: PageScore[] = [
      ...pageAudits.map(page => ({
        url: page.url,
        visibilityScore: page.score,
        criticalIssues: criticalIssueCounts.get(page.url) || 0,
        priority: page.score < 25 ? "critical" as const : page.score < 45 ? "high" as const : page.score < 65 ? "medium" as const : "low" as const,
        status: "analyzed" as const,
      })),
      ...crawl.failedUrls.map(failedUrl => ({
        url: failedUrl,
        visibilityScore: null,
        criticalIssues: 0,
        priority: "low" as const,
        status: "inaccessible" as const,
      })),
    ];

    const result: AuditResult = {
      score: overallScore,
      band: bandFromScore(overallScore),
      citability: citabilityScore,
      scoreBreakDown: {
        structuredData: schemaRes.score,
        aiCitability: citRes.score,
        eeat: eeatRes.score,
        technical: techRes.score,
        contentQuality: contentRes.score,
        brandAuthority: brandRes.score,
      },
      categoryDetails,
      criticalIssues: issues.filter(issue => issue.severity === "critical"),
      issues,
      quickWins,
      aiPlatforms,
      entities,
      contentMetrics,
      roadmap,
      pagesAnalyzed,
      crawlSummary: {
        batchSize: batchMode ? CRAWL_BATCH_SIZE : INITIAL_CRAWL_PAGE_LIMIT,
        pagesDiscovered: crawl.pagesDiscovered,
        pagesAttempted: crawl.attemptedUrls.length,
        pagesAnalyzed: crawl.pages.length,
        failedPages: crawl.failedUrls.length,
        skippedByRobots: crawl.skippedByRobots,
        truncated: crawl.truncated,
        subdomainsIncluded: includeSubdomains,
      },
      recommendations: allRecs,
      checkedAt: new Date().toISOString(),
    };

    return NextResponse.json(batchMode ? { ...result, crawlBatch } : result);
  } catch (error) {
    console.error("GEO audit error:", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Audit failed" },
      { status: 500 }
    );
  }
}
