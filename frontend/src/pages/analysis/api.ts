import { apiFetch } from "../../api/http";

/**
 * Parsed-record analysis endpoints. These are page-local wrappers over the
 * shared `apiFetch` client; they intentionally live here (not in the shared
 * resources module) because the Analysis surface owns them.
 */

/** One distinct ParsedRecord `type` present in the case, with its count. */
export interface RecordTypeCount {
  type: string;
  count: number;
}

export interface RecordTypesResponse {
  record_types: RecordTypeCount[];
}

/** One application the case holds records from (§2.12). */
export interface AppRecordCount {
  app: string;
  records: number;
  /** The record types that made up this group. */
  record_types: string[];
  /**
   * How the group was attributed: the record named the app
   * (`named_by_record`), its type is an app (`record_type`), or both reached
   * the same group. Carried because they are different confidences and a
   * screen should not present them as one.
   */
  attribution:
    | "named_by_record"
    | "record_type"
    | "named_by_record_and_record_type"
    | "unknown";
}

export interface AppRecordCountsResponse {
  apps: AppRecordCount[];
  total_records: number;
  /**
   * Records belonging to no application — file entries, registry keys,
   * network flows. Counted and NOT distributed among the apps, so the per-app
   * figures are not a breakdown of the whole case.
   */
  unattributed: {
    records: number;
    record_types: string[];
    note: string;
  };
}

/** Parsed fields are an untyped JSON object; viewers read known keys. */
export type RecordMetadata = Record<string, unknown>;

export interface ParsedRecord {
  id: string;
  parent_id: string | null;
  artifact_type: string;
  metadata: RecordMetadata;
}

export interface RecordsResponse {
  records: ParsedRecord[];
  /**
   * Records matching type + source scope + `q`. This is the denominator of an
   * "N of T" reading, and once `q` is applied it is the MATCHING population —
   * not the type's.
   */
  total: number;
  /**
   * The type's own population, ignoring `q`. Equal to `total` when no `q` was
   * given. The two together are what lets a screen say "312 of 2,100,000
   * match" rather than the unreadable "312".
   */
  type_total?: number;
  /**
   * Records in the type + scope population whose metadata would not parse and
   * which therefore could not be tested against `q` at all: neither matches
   * nor established non-matches. `null` — and, from a server that predates the
   * field, `undefined` — means the question was never asked because there was
   * no `q`. NEVER render either as 0: "nothing was unreadable" and "nobody
   * looked" are different findings.
   */
  unfilterable_metadata?: number | null;
  /**
   * Records of this type that a later run of the same module answered, which
   * the listing left out (HUNT-107). `null` — and `undefined` from a server
   * that predates the field — means nothing was excluded, because the request
   * asked for them. NEVER render either as 0.
   */
  superseded_total?: number | null;
  /** True iff a non-empty `q` was applied. */
  filtered?: boolean;
  q?: string | null;
  /** Echo of the keys the term was applied to. Empty when no `q` was given. */
  q_keys?: string[];
  /**
   * How the server matched. SQLite's LIKE folds ASCII case only, so "STRASSE"
   * finds "strasse" while "Straße" does not — which a screen an examiner works
   * a German-language device on has to say out loud.
   */
  q_match?: string;
  sort?: string | null;
  order?: SortOrder;
  /**
   * "metadata_key" when `sort` was given, "ingest" otherwise. Ingest order is
   * NOT event order: `order=desc` without a sort key means newest-INGESTED
   * first, and must never be labelled "most recent".
   */
  order_by?: "metadata_key" | "ingest";
  page: number;
  page_size: number;
  type: string;
}

export type SortOrder = "asc" | "desc";

/**
 * The endpoint refuses a request naming more than this many `q_keys` — it
 * refuses rather than trimming, so a caller that would exceed it has to decide
 * which keys it meant.
 */
export const Q_KEYS_MAX = 16;

/**
 * Distinct ParsedRecord types with counts. With `sourceId`, the counts are
 * scoped to that source acquisition's subtree, so the navigator can attribute
 * records to the acquisition they came from rather than blending every source.
 */
export const getRecordTypes = (caseId: string, sourceId?: string) =>
  apiFetch<RecordTypesResponse>(`/cases/${caseId}/record_types`, {
    query: { source_id: sourceId },
  });

/**
 * Records grouped by the application they came from: "what is on this device"
 * (§2.12). Scoped to one acquisition with `sourceId`.
 */
export const getAppRecordCounts = (caseId: string, sourceId?: string) =>
  apiFetch<AppRecordCountsResponse>(`/cases/${caseId}/stats/apps`, {
    query: { source_id: sourceId },
  });

export interface RecordsParams {
  type: string;
  page: number;
  page_size: number;
  source_id?: string;
  /**
   * Case-insensitive substring term. The server REFUSES `q` without `q_keys`
   * rather than guessing which keys a term applies to, so the two travel
   * together or not at all.
   */
  q?: string;
  /** Bare metadata key names the term is tested against. At most `Q_KEYS_MAX`. */
  q_keys?: string[];
  /** Bare metadata key to order by. Absent means ingest order. */
  sort?: string;
  order?: SortOrder;
  /** Ask for the records a later run answered, which are left out by default. */
  include_superseded?: boolean;
}

export const getRecords = (caseId: string, params: RecordsParams) =>
  apiFetch<RecordsResponse>(`/cases/${caseId}/records`, {
    query: {
      type: params.type,
      page: params.page,
      page_size: params.page_size,
      source_id: params.source_id,
      // Sent only as a pair. An empty string is a value as far as the query
      // builder is concerned, so "no term" has to be `undefined` here or the
      // server sees `q=` and refuses the request for a search nobody asked for.
      q: params.q && params.q_keys?.length ? params.q : undefined,
      q_keys:
        params.q && params.q_keys?.length ? params.q_keys.join(",") : undefined,
      sort: params.sort,
      // `order` alone means nothing without something to order by, and the
      // server defaults it anyway.
      order: params.sort ? params.order : undefined,
      // Sent only when asking for them: the default is the server's, and a
      // `false` on every request would be noise in the audit log.
      include_superseded: params.include_superseded ? "true" : undefined,
    },
  });

export interface AllRecordsResult {
  records: ParsedRecord[];
  total: number;
  /** True when a page cap stopped us short of `total`. */
  truncated: boolean;
}

/**
 * Aggregate viewers (conversations, database browser, agenda) need the whole
 * dataset, not one page. Walk pages up to `maxPages` and concatenate. Page
 * counting uses the server's echoed `page_size` so a clamped page size still
 * yields the right number of requests.
 */
export async function getAllRecords(
  caseId: string,
  type: string,
  opts: { maxPages?: number; pageSize?: number; source_id?: string } = {},
): Promise<AllRecordsResult> {
  const pageSize = opts.pageSize ?? 100;
  const maxPages = opts.maxPages ?? 8;
  const first = await getRecords(caseId, {
    type,
    page: 1,
    page_size: pageSize,
    source_id: opts.source_id,
  });
  const effective = first.page_size || pageSize;
  const totalPages = Math.max(Math.ceil(first.total / effective), 1);
  const cap = Math.min(totalPages, maxPages);
  const records = [...first.records];
  if (cap > 1) {
    // Pages 2..cap are independent once page 1 has given us the total, so fetch
    // them concurrently instead of walking one round-trip at a time. First paint
    // is then <=2 RTT (page 1, then the rest as a single parallel batch), and
    // Promise.all preserves page order so concatenation stays in order.
    const rest = await Promise.all(
      Array.from({ length: cap - 1 }, (_, i) =>
        getRecords(caseId, {
          type,
          page: i + 2,
          page_size: pageSize,
          source_id: opts.source_id,
        }),
      ),
    );
    for (const next of rest) records.push(...next.records);
  }
  return {
    records,
    total: first.total,
    truncated: records.length < first.total,
  };
}

/**
 * Resolve backup-relative file paths (chat attachments record the on-device
 * path of their media, not a link to the extracted file) to the artifacts
 * holding those bytes. Batched: one call covers a whole conversation. Paths
 * with no match in the evidence are simply absent from the result.
 */
export async function resolveFiles(
  caseId: string,
  paths: string[],
): Promise<Record<string, string>> {
  if (paths.length === 0) return {};
  // Chunked well inside the endpoint's own cap: asking for more than it accepts
  // fails the whole request, which reads as "none of this media is in the
  // evidence" when in fact nothing was looked up.
  const CHUNK = 500;
  const matches: Record<string, string> = {};
  for (let i = 0; i < paths.length; i += CHUNK) {
    const res = await apiFetch<{ matches: Record<string, string> }>(
      `/cases/${caseId}/files/resolve`,
      { method: "POST", body: { paths: paths.slice(i, i + CHUNK) } },
    );
    Object.assign(matches, res.matches);
  }
  return matches;
}

/** One correspondent/thread, aggregated server-side. */
export interface ConversationSummary {
  key: string;
  label: string;
  count: number;
  last_time: number;
  last_preview: string | null;
  is_group: boolean;
  tag: string | null;
}

/**
 * Every conversation in a messaging type. Aggregated in SQL, so the complete
 * correspondent list arrives in one small response no matter how many messages
 * the database holds — the messages themselves are fetched per thread.
 */
export async function getConversations(
  caseId: string,
  type: string,
): Promise<ConversationSummary[]> {
  const res = await apiFetch<{ conversations: ConversationSummary[] }>(
    `/cases/${caseId}/conversations`,
    { query: { type } },
  );
  return res.conversations;
}

/**
 * One page of a conversation, newest first. `before` is a scrollback cursor in
 * epoch seconds: messages strictly older than it.
 */
export interface ConversationPage {
  records: ParsedRecord[];
  /** Media belonging to exactly these messages, resolved server-side. */
  attachments: ParsedRecord[];
  /**
   * True when the server's attachment fetch hit its row cap, so `attachments`
   * is a subset of the media belonging to these messages.
   *
   * `Database::attachments_for_messages` returns this precisely so a client can
   * say it: a media-rich page that comes back at exactly the cap is byte-for-byte
   * the same as one that happens to hold that many, and an examiner reading
   * "12 photos in this conversation" must not be looking at a silently
   * shortened list. Discarding it made every capped page render as complete.
   */
  attachmentsTruncated: boolean;
  /**
   * Where the next page resumes, straight from the server. Null at the end of
   * the thread.
   *
   * Both halves travel together on purpose. Messages can share an ordering
   * value, so resuming from the ordering value alone drops every message that
   * shares it with the last one on the page — silently, in the middle of a
   * conversation. The server refuses a half-cursor with a 400 rather than
   * serve that.
   */
  nextCursor: ConversationCursor | null;
  /**
   * True when the server has more messages past this page.
   *
   * Read from the server rather than inferred from `records.length`: a page
   * shortened by undecodable rows comes back below the limit while more
   * messages exist, and inferring the end from a short page called such a
   * thread finished.
   */
  hasMore: boolean;
  /**
   * Messages this page fetched and could not decode. The thread on screen is
   * short by this many messages that DO exist in the evidence, which must
   * never render as a gap in the conversation.
   */
  undecodable: number;
}

/** A scrollback position: an ordering value AND the id that breaks its ties. */
export interface ConversationCursor {
  before: number;
  before_id: string;
}

export async function getConversationMessages(
  caseId: string,
  type: string,
  key: string,
  cursor?: ConversationCursor | null,
  limit = 60,
): Promise<ConversationPage> {
  const res = await apiFetch<{
    records: ParsedRecord[];
    attachments?: ParsedRecord[];
    attachments_truncated?: boolean;
    next_cursor?: ConversationCursor | null;
    has_more?: boolean;
    undecodable?: number;
  }>(`/cases/${caseId}/conversations/messages`, {
    // Both halves or neither. Sending `before` alone is a 400 by the server's
    // contract, which is what every scrollback page did before this.
    query: {
      type,
      key,
      before: cursor?.before,
      before_id: cursor?.before_id,
      limit,
    },
  });
  return {
    records: res.records,
    attachments: res.attachments ?? [],
    attachmentsTruncated: res.attachments_truncated === true,
    nextCursor: res.next_cursor ?? null,
    hasMore: res.has_more === true,
    undecodable: typeof res.undecodable === "number" ? res.undecodable : 0,
  };
}

/** A message matching a chat search, tagged with its conversation. */
export interface ConversationSearchHit {
  id: string;
  thread_key: string;
  text: string;
  date: number;
}

/**
 * The result of a chat search, with the server's own statement about whether it
 * is the whole match set.
 *
 * The endpoint stops at `limit` without counting past it, so a full page and a
 * complete answer are the same bytes on the wire unless the server labels them
 * — which it does, and this client used to discard the label and return the
 * bare hit array. "37 matches" then meant "the first 37 of an unknown number"
 * in a chat search, on the surface most likely to be quoted in court.
 */
export interface ConversationSearchResult {
  hits: ConversationSearchHit[];
  /** The limit the server actually applied, after its own clamp. */
  limit: number;
  /** True when messages match that are not in `hits`. */
  truncated: boolean;
  /** True when `hits.length` is a floor for the match count, not the total. */
  count_is_lower_bound: boolean;
}

export async function searchConversations(
  caseId: string,
  type: string,
  q: string,
  limit = 100,
): Promise<ConversationSearchResult> {
  const res = await apiFetch<{
    hits: ConversationSearchHit[];
    limit?: number;
    truncated?: boolean;
    count_is_lower_bound?: boolean;
  }>(`/cases/${caseId}/conversations/search`, { query: { type, q, limit } });
  return {
    hits: res.hits,
    // A server that reported no limit is not a server that applied none; fall
    // back to the limit we asked for rather than to a number that would read as
    // "unlimited".
    limit: typeof res.limit === "number" ? res.limit : limit,
    truncated: res.truncated === true,
    count_is_lower_bound: res.count_is_lower_bound === true,
  };
}

/** One correspondent in the server-computed communications ranking. */
export interface RankedContact {
  /** The counterparty exactly as the parsers recorded it. */
  contact: string;
  count: number;
}

/**
 * The most-contacted league table, counted in SQL over the whole case.
 *
 * Every field here names a DIFFERENT population, and the note the page prints
 * under the bars has to keep them apart, so they are kept apart in the type:
 *
 * - `contacts` and `distinct_contacts` are narrowed by the search needle `q`.
 *   `distinct_contacts` is the exact number of matching correspondents and is
 *   NOT capped by `limit`, so it is what "the top 8 of 4,211" is counted from.
 * - `by_type` and the four `*_records` counts describe the CASE, narrowed by
 *   `channel` alone. They are never narrowed by `q` and must never be
 *   presented as search results.
 * - `unrankable_records` and `records_without_counterparty` are two different
 *   facts and must not be added together: the first is records carrying none
 *   of the counterparty keys at all, the second is call-log rows the device
 *   itself recorded with no number, which the parser writes as the literal
 *   string "Unknown". The server excludes those from the ranking rather than
 *   seat a phantom party called "Unknown" at the top of the table — but the
 *   calls did happen, so the count has to stay visible.
 *
 * A number the server did not send arrives as `null`, never as `0`: "the
 * server did not state how many calls had no number" and "no call had no
 * number" are different claims, and only one of them is ours to make.
 */
export interface CommsRanking {
  contacts: RankedContact[];
  /** The limit the server actually applied, after its own clamp. */
  limit: number | null;
  /** True when correspondents match `q` that are not in `contacts`. */
  has_more: boolean | null;
  /** Distinct correspondents matching `q`, independent of `limit`. */
  distinct_contacts: number | null;
  /** Case record counts per ParsedRecord type name, e.g. `["AndroidSms", 500]`. */
  by_type: [string, number][] | null;
  total_records: number | null;
  summary_records: number | null;
  unrankable_records: number | null;
  records_without_counterparty: number | null;
}

/** A finite number, or null when the server said nothing we can read. */
function statedNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/**
 * Read `by_type` whole or not at all. A pair we cannot parse is dropped only by
 * dropping the entire breakdown, because the page prints this list as the
 * population the ranking covers: quietly omitting one type would understate
 * that population while still reading as a complete inventory.
 */
function statedByType(value: unknown): [string, number][] | null {
  if (!Array.isArray(value)) return null;
  const out: [string, number][] = [];
  for (const pair of value) {
    if (!Array.isArray(pair) || pair.length !== 2) return null;
    const [type, count] = pair;
    if (typeof type !== "string" || statedNumber(count) == null) return null;
    out.push([type, count as number]);
  }
  return out;
}

export interface CommsRankingParams {
  /** A single ParsedRecord type name ("AndroidSms"), not a channel label. */
  channel?: string;
  /** Case-insensitive substring match on the counterparty. */
  q?: string;
  limit?: number;
}

/**
 * Rank the correspondents in a case server-side.
 *
 * A malformed `contacts` array throws rather than being coerced: the caller's
 * fallback is its own honestly-labelled slice ranking, which is a far better
 * outcome than invented rows presented under the word "exact".
 */
export async function getCommsRanking(
  caseId: string,
  params: CommsRankingParams,
): Promise<CommsRanking> {
  const res = await apiFetch<Record<string, unknown>>(
    `/cases/${caseId}/comms/ranking`,
    {
      query: {
        channel: params.channel,
        q: params.q,
        limit: params.limit,
      },
    },
  );

  if (!Array.isArray(res.contacts)) {
    throw new Error("comms ranking: response carried no contacts array");
  }
  const contacts: RankedContact[] = res.contacts.map((row) => {
    const contact = (row as RankedContact | null)?.contact;
    const count = statedNumber((row as RankedContact | null)?.count);
    if (typeof contact !== "string" || count == null) {
      throw new Error(
        "comms ranking: contacts held a row that is not a ranking",
      );
    }
    return { contact, count };
  });

  return {
    contacts,
    limit: statedNumber(res.limit),
    has_more: typeof res.has_more === "boolean" ? res.has_more : null,
    distinct_contacts: statedNumber(res.distinct_contacts),
    by_type: statedByType(res.by_type),
    total_records: statedNumber(res.total_records),
    summary_records: statedNumber(res.summary_records),
    unrankable_records: statedNumber(res.unrankable_records),
    records_without_counterparty: statedNumber(
      res.records_without_counterparty,
    ),
  };
}

/** One bar of the server-side communications histogram. */
export interface CommsHistogramBucket {
  /**
   * Inclusive start of the bucket, in whole Unix SECONDS.
   *
   * The unit is in the name because the charts that draw this work in
   * milliseconds: a value handed to `new Date()` in the wrong unit renders
   * 2024 as 1970-01-20, which is a wrong answer that looks like a right one.
   */
  bucket_start_secs: number;
  count: number;
  /**
   * Of `count`, how many were placed ONLY by assuming which unit the parser
   * wrote — milliseconds, microseconds, FILETIME ticks — rather than reading
   * the value as the whole seconds its contract states.
   *
   * Null where the server did not state it, which is not zero: "none of these
   * bars rests on an assumption" is a claim about the evidence, and a silent
   * default would make it on the server's behalf.
   */
  rescued_count: number | null;
}

/**
 * Volume over time for a case's communications, counted in SQL.
 *
 * Two populations meet here and never merge, exactly as in `CommsRanking`:
 * `total_records` is the case narrowed by `channel` ALONE — never by the search
 * needle or the contact filter, because a total that shrank while an examiner
 * typed would read as evidence disappearing — while `matched_records` is
 * narrowed by all three and is the population the bars and the whole census
 * describe.
 *
 * The census is ORDERED, not summed twice: a call-log summary row carries no
 * time key either, so counting it under both `not_a_message` and
 * `unplaceable_absent` would produce a census larger than the population it
 * describes. Each matched record lands in exactly one class.
 */
export interface CommsHistogram {
  buckets: CommsHistogramBucket[];
  /** Width of every bucket in seconds. Null only where there are no bars. */
  bucket_seconds: number | null;
  /** Extent of the placed records, in seconds. Null where none were placed. */
  min_ts_secs: number | null;
  max_ts_secs: number | null;
  /** The case, narrowed by `channel` alone. */
  total_records: number | null;
  /** Narrowed by channel, needle and contact. The bars sum to its placed part. */
  matched_records: number | null;
  /** Matched records whose `metadata_json` does not parse at all. */
  unreadable_metadata: number | null;
  /** Matched rows that are not messages: a summary row, or a parser status stub. */
  not_a_message: number | null;
  /** Matched; every time key absent or JSON null. */
  unplaceable_absent: number | null;
  /** Matched; a key was there and no reading of it is admissible. */
  unplaceable_value: number | null;
  /** Matched; placed only by assuming which unit the parser used. */
  placed_by_rescue: number | null;
  /** Matched; read to contract. */
  placed_as_written: number | null;
  /** Unplaceable matched records per ParsedRecord type, e.g. `["CallLog", 123]`. */
  by_type_unplaceable: [string, number][] | null;
}

export interface CommsHistogramParams {
  /** A single ParsedRecord type name ("AndroidSms"), not a channel label. */
  channel?: string;
  /** Case-insensitive substring match on the counterparty. */
  q?: string;
  /** Narrow to one counterparty, exactly as the parsers recorded it. */
  contact?: string;
  /** How many bars to aim for; the server picks the bucket width from it. */
  buckets?: number;
}

/** One bucket, or a refusal. A bar we cannot state the start and size of is not a bar. */
function statedBucket(row: unknown): CommsHistogramBucket {
  const r = row as Partial<CommsHistogramBucket> | null;
  const start = statedNumber(r?.bucket_start_secs);
  const count = statedNumber(r?.count);
  if (start == null || count == null) {
    throw new Error("comms histogram: buckets held a row that is not a bucket");
  }
  return {
    bucket_start_secs: start,
    count,
    rescued_count: statedNumber(r?.rescued_count),
  };
}

/**
 * Hold the response to the invariants it states about itself, and refuse it
 * whole where they do not hold.
 *
 * This is deliberately harsher than dropping the offending field. Every number
 * in this response is a claim about the same population, and the page prints
 * them beside each other as one paragraph: bars that sum to 411 above a
 * sentence saying 412 records were placed is not a slightly-wrong chart, it is
 * a chart and a caption that cannot both be quoted. The caller's fallback is
 * its own honestly-labelled client-side chart, which is a worse answer but a
 * defensible one.
 *
 * Only STATED fields take part. A field the server did not send is not a zero
 * to check against — it is a claim that was never made, and an invariant
 * cannot be violated by a silence.
 */
function checkInvariants(h: CommsHistogram): void {
  const drawn = h.buckets.reduce((n, b) => n + b.count, 0);

  const census = [
    h.unreadable_metadata,
    h.not_a_message,
    h.unplaceable_absent,
    h.unplaceable_value,
    h.placed_by_rescue,
    h.placed_as_written,
  ];
  if (h.matched_records != null && census.every((c) => c != null)) {
    const sum = census.reduce((n, c) => n + (c as number), 0);
    if (sum !== h.matched_records) {
      throw new Error(
        `comms histogram: the census sums to ${sum} where ${h.matched_records} records matched`,
      );
    }
  }

  if (h.placed_by_rescue != null && h.placed_as_written != null) {
    const placed = h.placed_by_rescue + h.placed_as_written;
    if (drawn !== placed) {
      throw new Error(
        `comms histogram: the bars sum to ${drawn} where ${placed} records were said to be placed`,
      );
    }
  }

  if (
    h.placed_by_rescue != null &&
    h.buckets.every((b) => b.rescued_count != null)
  ) {
    const rescued = h.buckets.reduce(
      (n, b) => n + (b.rescued_count as number),
      0,
    );
    if (rescued !== h.placed_by_rescue) {
      throw new Error(
        `comms histogram: the bars carry ${rescued} rescued records where ${h.placed_by_rescue} were said to be rescued`,
      );
    }
  }

  if (
    h.total_records != null &&
    h.matched_records != null &&
    h.total_records < h.matched_records
  ) {
    throw new Error(
      `comms histogram: ${h.matched_records} records matched out of a case of ${h.total_records}`,
    );
  }

  // An extent and the bars have to agree about whether anything was placed at
  // all, because the axis is drawn from one and the bars from the other.
  if ((h.min_ts_secs != null) !== drawn > 0) {
    throw new Error(
      h.min_ts_secs != null
        ? "comms histogram: an extent was stated over bars that place nothing"
        : "comms histogram: bars were drawn with no extent to place them in",
    );
  }

  // Without a width, the only thing a bar can be drawn as is the instant it
  // starts at — and a bucket that may be 22 days wide is exactly not that.
  if (h.buckets.length > 0 && h.bucket_seconds == null) {
    throw new Error(
      "comms histogram: bars arrived with no stated bucket_seconds width",
    );
  }
}

/**
 * Volume over time for the communications in a case, counted server-side.
 *
 * Throws rather than coerces, for the reason `getCommsRanking` does and one
 * more: a histogram is a claim about WHEN things happened, and it is read at a
 * glance. There is no version of a wrong bar that an examiner can be expected
 * to catch.
 */
export async function getCommsHistogram(
  caseId: string,
  params: CommsHistogramParams,
): Promise<CommsHistogram> {
  const res = await apiFetch<Record<string, unknown>>(
    `/cases/${caseId}/comms/histogram`,
    {
      query: {
        channel: params.channel,
        q: params.q,
        contact: params.contact,
        buckets: params.buckets,
      },
    },
  );

  if (!Array.isArray(res.buckets)) {
    throw new Error("comms histogram: response carried no buckets array");
  }

  const histogram: CommsHistogram = {
    buckets: res.buckets.map(statedBucket),
    bucket_seconds: statedNumber(res.bucket_seconds),
    min_ts_secs: statedNumber(res.min_ts_secs),
    max_ts_secs: statedNumber(res.max_ts_secs),
    total_records: statedNumber(res.total_records),
    matched_records: statedNumber(res.matched_records),
    unreadable_metadata: statedNumber(res.unreadable_metadata),
    not_a_message: statedNumber(res.not_a_message),
    unplaceable_absent: statedNumber(res.unplaceable_absent),
    unplaceable_value: statedNumber(res.unplaceable_value),
    placed_by_rescue: statedNumber(res.placed_by_rescue),
    placed_as_written: statedNumber(res.placed_as_written),
    by_type_unplaceable: statedByType(res.by_type_unplaceable),
  };
  checkInvariants(histogram);
  return histogram;
}
