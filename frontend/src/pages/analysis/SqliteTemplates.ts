/**
 * Query templates for the SQLite query editor: one real, single-statement
 * SELECT per artifact database the tree already parses.
 *
 * Every template names the real fixture it was proven against (`fixture`,
 * repository-relative), and `SqliteTemplates.test.ts` re-runs each statement
 * over that file with the sqlite3 CLI. A template for a schema no fixture on
 * hand could prove is not in this list — WhatsApp `msgstore.db` and
 * `ChatStorage.sqlite`, for instance, have no sample in the tree.
 *
 * Timestamp columns are decoded in SQL only where the epoch is fixed by the
 * schema (WebKit microseconds, PRTime, Unix milliseconds). Where one schema
 * has carried two units across versions (iOS `message.date`) the raw value is
 * kept beside a column whose name says it was decoded by magnitude, and the
 * examiner can re-interpret the raw column in the result grid.
 */

export interface SqliteQueryTemplate {
  id: string
  title: string
  /** The artifact database this is for, as an examiner names it. */
  artifact: string
  /**
   * Tables the statement reads. A database whose schema lacks one of these
   * cannot run the template, and the editor says which are missing.
   */
  requires: string[]
  sql: string
  /** What the columns mean and any inference the statement makes. */
  notes: string
  /** Repository-relative path of the real database this statement was run over. */
  fixture: string
}

/** Chrome/WebKit: microseconds since 1601-01-01 → Unix seconds. */
const WEBKIT = (col: string) =>
  `datetime(${col} / 1000000 - 11644473600, 'unixepoch')`
/** Firefox PRTime: microseconds since 1970. */
const PRTIME = (col: string) => `datetime(${col} / 1000000, 'unixepoch')`
/** Android: milliseconds since 1970. */
const UNIX_MS = (col: string) => `datetime(${col} / 1000, 'unixepoch')`
const UNIX_S = (col: string) => `datetime(${col}, 'unixepoch')`
/** Cocoa / Core Data: seconds since 2001-01-01. */
const COCOA_S = (col: string) => `datetime(${col} + 978307200, 'unixepoch')`

export const SQLITE_QUERY_TEMPLATES: SqliteQueryTemplate[] = [
  {
    id: 'schema',
    title: 'Schema: every table, index, view and trigger',
    artifact: 'Any SQLite database',
    requires: [],
    sql: `SELECT type, name, tbl_name, sql
FROM sqlite_master
ORDER BY type, name`,
    notes:
      'The CREATE statements as stored in the file. Reads the schema table only, so it applies to any database.',
    fixture: 'reference/plaso/test_data/chrome_history/History',
  },
  {
    id: 'chrome_urls',
    title: 'Chrome / Chromium History: URLs by last visit',
    artifact: 'Chrome, Chromium, Edge, Brave `History`',
    requires: ['urls'],
    sql: `SELECT id, url, title, visit_count, typed_count,
       ${WEBKIT('last_visit_time')} AS last_visit_utc, hidden
FROM urls
ORDER BY last_visit_time DESC
LIMIT 500`,
    notes:
      'last_visit_utc decodes WebKit microseconds since 1601. visit_count is the browser’s own tally, not a count of rows in visits.',
    fixture: 'reference/plaso/test_data/chrome_history/History',
  },
  {
    id: 'chrome_visits',
    title: 'Chrome / Chromium History: visits with transition',
    artifact: 'Chrome, Chromium, Edge, Brave `History`',
    requires: ['visits', 'urls'],
    sql: `SELECT v.id, u.url, u.title,
       ${WEBKIT('v.visit_time')} AS visit_utc,
       v.transition & 255 AS transition_core, v.from_visit
FROM visits v
JOIN urls u ON u.id = v.url
ORDER BY v.visit_time DESC
LIMIT 500`,
    notes:
      'transition_core is the low byte of the transition mask (0 link, 1 typed, 2 auto bookmark, 3 auto subframe, 4 manual subframe, 5 generated, 6 auto toplevel, 7 form submit, 8 reload, 9 keyword, 10 keyword generated); the qualifier bits are dropped.',
    fixture: 'reference/plaso/test_data/chrome_history/History',
  },
  {
    id: 'chrome_search_terms',
    title: 'Chrome / Chromium History: search terms',
    artifact: 'Chrome, Chromium, Edge, Brave `History`',
    requires: ['keyword_search_terms', 'urls'],
    sql: `SELECT k.term, u.url,
       ${WEBKIT('u.last_visit_time')} AS last_visit_utc
FROM keyword_search_terms k
JOIN urls u ON u.id = k.url_id
ORDER BY u.last_visit_time DESC
LIMIT 500`,
    notes:
      'Terms the browser recognised as searches on a known engine. last_visit_utc is the URL row’s last visit, not necessarily the search’s.',
    fixture: 'reference/plaso/test_data/chrome_history/History',
  },
  {
    id: 'firefox_visits',
    title: 'Firefox places: history visits',
    artifact: 'Firefox `places.sqlite`',
    requires: ['moz_historyvisits', 'moz_places'],
    sql: `SELECT v.id, p.url, p.title,
       ${PRTIME('v.visit_date')} AS visit_utc,
       v.visit_type, v.from_visit
FROM moz_historyvisits v
JOIN moz_places p ON p.id = v.place_id
ORDER BY v.visit_date DESC
LIMIT 500`,
    notes:
      'visit_utc decodes PRTime microseconds since 1970. visit_type: 1 link, 2 typed, 3 bookmark, 4 embed, 5 permanent redirect, 6 temporary redirect, 7 download, 8 framed link, 9 reload.',
    fixture: 'reference/plaso/test_data/firefox_history/places.sqlite',
  },
  {
    id: 'firefox_bookmarks',
    title: 'Firefox places: bookmarks',
    artifact: 'Firefox `places.sqlite`',
    requires: ['moz_bookmarks', 'moz_places'],
    sql: `SELECT b.id, b.title, p.url,
       ${PRTIME('b.dateAdded')} AS added_utc,
       ${PRTIME('b.lastModified')} AS modified_utc
FROM moz_bookmarks b
JOIN moz_places p ON p.id = b.fk
WHERE b.type = 1
ORDER BY b.dateAdded DESC
LIMIT 500`,
    notes: 'type = 1 keeps bookmark entries; folders (2) and separators (3) are left out.',
    fixture: 'reference/plaso/test_data/firefox_history/places.sqlite',
  },
  {
    id: 'chrome_cookies',
    title: 'Chrome / Chromium Cookies',
    artifact: 'Chrome, Chromium, Edge, Brave `Cookies`',
    requires: ['cookies'],
    sql: `SELECT host_key, name, path,
       ${WEBKIT('creation_utc')} AS created_utc,
       ${WEBKIT('expires_utc')} AS expires_utc,
       ${WEBKIT('last_access_utc')} AS last_access_utc,
       length(value) AS value_bytes
FROM cookies
ORDER BY creation_utc DESC
LIMIT 500`,
    notes:
      'Only columns every Chromium cookie schema carries are read; the secure/httponly flags were renamed between versions and are left to the grid. value_bytes is the stored (possibly encrypted) length, not the cookie text.',
    fixture: 'reference/plaso/test_data/cookies.db',
  },
  {
    id: 'chrome_autofill',
    title: 'Chrome / Chromium Web Data: autofill entries',
    artifact: 'Chrome, Chromium, Edge, Brave `Web Data`',
    requires: ['autofill'],
    sql: `SELECT name, value, count,
       ${UNIX_S('date_created')} AS created_utc,
       ${UNIX_S('date_last_used')} AS last_used_utc
FROM autofill
ORDER BY date_last_used DESC
LIMIT 500`,
    notes: 'Form-field names and the values typed into them. Timestamps are Unix seconds.',
    fixture: 'reference/plaso/test_data/Web Data',
  },
  {
    id: 'ios_messages',
    title: 'iOS sms.db / macOS chat.db: messages with handle',
    artifact: 'iOS `sms.db`, macOS `chat.db`',
    requires: ['message', 'handle'],
    sql: `SELECT m.ROWID, h.id AS handle,
       CASE m.is_from_me WHEN 1 THEN 'sent' WHEN 0 THEN 'received' ELSE m.is_from_me END AS direction,
       m.service, m.date AS date_raw,
       CASE WHEN m.date > 0 THEN ${COCOA_S('CASE WHEN m.date > 1000000000000 THEN m.date / 1000000000 ELSE m.date END')} END AS date_utc_by_magnitude,
       m.text
FROM message m
LEFT JOIN handle h ON h.ROWID = m.handle_id
ORDER BY m.date DESC
LIMIT 500`,
    notes:
      'date_utc_by_magnitude is an inference: message.date is Cocoa seconds on older builds and Cocoa nanoseconds from iOS 11 / macOS 10.13, and the statement picks the unit by the size of the value, with the threshold Séance\'s own parsers use (a value above 10^12 is nanoseconds). A date of 0 or less is left empty rather than shown as 2001-01-01. The named fixture holds seconds-scale values only; the nanosecond branch was checked against the 13 messages of a real iOS 15 sms.db (Magnet 2022 iPhone 8), which is not in the tree. Seconds are whole: sub-second digits are dropped. date_raw is kept so the choice can be checked in the grid. text is NULL for messages whose body lives only in attributedBody.',
    fixture: 'reference/plaso/test_data/imessage_chat.db',
  },
  {
    id: 'ios_chats',
    title: 'iOS sms.db / macOS chat.db: chats and their message counts',
    artifact: 'iOS `sms.db`, macOS `chat.db`',
    requires: ['chat', 'chat_message_join'],
    sql: `SELECT c.ROWID, c.chat_identifier, c.display_name, c.service_name,
       COUNT(j.message_id) AS messages_joined
FROM chat c
LEFT JOIN chat_message_join j ON j.chat_id = c.ROWID
GROUP BY c.ROWID
ORDER BY messages_joined DESC
LIMIT 500`,
    notes:
      'messages_joined counts join rows, which is the number of messages the database still links to the chat, not the number ever exchanged.',
    fixture: 'reference/plaso/test_data/imessage_chat.db',
  },
  {
    id: 'ios_attachments',
    title: 'iOS sms.db / macOS chat.db: attachments',
    artifact: 'iOS `sms.db`, macOS `chat.db`',
    requires: ['attachment', 'message_attachment_join'],
    sql: `SELECT a.ROWID, a.filename, a.mime_type, a.total_bytes,
       a.created_date AS created_raw, j.message_id
FROM attachment a
LEFT JOIN message_attachment_join j ON j.attachment_id = a.ROWID
ORDER BY a.ROWID
LIMIT 500`,
    notes:
      'created_raw is left undecoded for the same seconds/nanoseconds reason as message.date; interpret it in the grid.',
    fixture: 'reference/plaso/test_data/imessage_chat.db',
  },
  {
    id: 'android_sms',
    title: 'Android mmssms.db: SMS',
    artifact: 'Android `mmssms.db`',
    requires: ['sms'],
    sql: `SELECT _id, thread_id, address,
       ${UNIX_MS('date')} AS date_utc,
       CASE type WHEN 1 THEN 'inbox' WHEN 2 THEN 'sent' WHEN 3 THEN 'draft' WHEN 4 THEN 'outbox'
                 WHEN 5 THEN 'failed' WHEN 6 THEN 'queued' ELSE type END AS box,
       read, body
FROM sms
ORDER BY date DESC
LIMIT 500`,
    notes: 'date_utc decodes Unix milliseconds. box names the Android message-box constant; an unknown value is shown as its number.',
    fixture: 'reference/plaso/test_data/mmssms.db',
  },
  {
    id: 'android_calls',
    title: 'Android contacts2.db: call log',
    artifact: 'Android `contacts2.db` / `calllog.db`',
    requires: ['calls'],
    sql: `SELECT _id, number,
       ${UNIX_MS('date')} AS date_utc,
       duration,
       CASE type WHEN 1 THEN 'incoming' WHEN 2 THEN 'outgoing' WHEN 3 THEN 'missed' WHEN 4 THEN 'voicemail'
                 WHEN 5 THEN 'rejected' WHEN 6 THEN 'blocked' ELSE type END AS direction,
       name
FROM calls
ORDER BY date DESC
LIMIT 500`,
    notes: 'duration is seconds. direction names the Android call-type constant; an unknown value is shown as its number.',
    fixture: 'reference/plaso/test_data/contacts2.db',
  },
  {
    id: 'skype_messages',
    title: 'Skype main.db: messages',
    artifact: 'Skype `main.db`',
    requires: ['Messages'],
    sql: `SELECT id, chatname, author, from_dispname,
       ${UNIX_S('timestamp')} AS sent_utc,
       type, body_xml
FROM Messages
ORDER BY timestamp DESC
LIMIT 500`,
    notes: 'body_xml is the message as Skype stored it, markup included.',
    fixture: 'reference/plaso/test_data/skype_main.db',
  },
  {
    id: 'kik_messages',
    title: 'Kik (iOS) kik.sqlite: messages with sender',
    artifact: 'Kik iOS `kik.sqlite`',
    requires: ['ZKIKMESSAGE', 'ZKIKUSER'],
    sql: `SELECT m.Z_PK, u.ZUSERNAME, u.ZDISPLAYNAME,
       ${COCOA_S('m.ZTIMESTAMP')} AS sent_utc,
       m.ZTYPE, m.ZBODY
FROM ZKIKMESSAGE m
LEFT JOIN ZKIKUSER u ON u.Z_PK = m.ZUSER
ORDER BY m.ZTIMESTAMP DESC
LIMIT 500`,
    notes: 'sent_utc decodes Core Data seconds since 2001.',
    fixture: 'reference/plaso/test_data/kik_ios.sqlite',
  },
  {
    id: 'win_timeline',
    title: 'Windows Timeline ActivitiesCache.db: activities',
    artifact: 'Windows `ActivitiesCache.db`',
    requires: ['Activity'],
    sql: `SELECT hex(Id) AS id, AppId, ActivityType,
       ${UNIX_S('StartTime')} AS start_utc,
       ${UNIX_S('EndTime')} AS end_utc,
       ${UNIX_S('LastModifiedTime')} AS modified_utc,
       ${UNIX_S('ExpirationTime')} AS expires_utc
FROM Activity
ORDER BY StartTime DESC
LIMIT 500`,
    notes: 'AppId is the JSON application list as stored. Times are Unix seconds; a NULL EndTime is an activity that was never closed.',
    fixture: 'reference/plaso/test_data/windows_timeline_ActivitiesCache.db',
  },
]

export interface TemplateApplicability {
  applicable: boolean
  /** Required tables the schema lacks; empty when applicable or unknown. */
  missing: string[]
  /**
   * False when no schema table list was available. Every template is then
   * offered, because "no list" is not "these tables are absent".
   */
  schemaKnown: boolean
}

export function templateApplicability(
  t: SqliteQueryTemplate,
  tableNames: string[],
): TemplateApplicability {
  if (tableNames.length === 0) {
    return { applicable: true, missing: [], schemaKnown: false }
  }
  const missing = t.requires.filter((r) => !tableNames.includes(r))
  return { applicable: missing.length === 0, missing, schemaKnown: true }
}
