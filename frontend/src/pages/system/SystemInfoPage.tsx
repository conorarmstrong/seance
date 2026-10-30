import { useQuery } from "@tanstack/react-query";
import { useParams } from "react-router-dom";
import {
  getDeviceInfo,
  getSystemInfo,
  type DeviceFact,
  type MobileDevice,
  type SystemIdentityConflict,
  type SystemInfo,
  type UnparsedHive,
} from "../../api/resources";
import { useSourceFilter } from "../../lib/useSourceFilter";
import { SourceSelect } from "../../components/SourceSelect";
import { formatUtc } from "../../lib/format";
import "./system.css";

const MISSING = "—";

function val(v: string | null | undefined): string {
  return v && v.length ? v : MISSING;
}

/**
 * A timestamp field, in the same form every other screen writes one.
 *
 * The API answers these as RFC 3339 with the precision the registry held —
 * `2004-08-27T15:46:33.109216400+00:00` — and this page was printing that
 * verbatim while the artifact viewer, the timeline and the reports all read
 * `2004-08-27 15:46:33 UTC`. One product should write a time one way; an
 * examiner comparing two screens should not have to notice they are the same
 * instant.
 */
function timeVal(v: string | null | undefined): string {
  return v && v.length ? formatUtc(v) : MISSING;
}

/**
 * One label/value row in a fact table.
 *
 * A field the hives disagree about arrives as `null`, exactly like a field the
 * evidence never held. Rendering both as a dash would erase the difference
 * between "this machine has no recorded computer name" and "two hives in this
 * case name two different machines" — so the disagreement is shown, with every
 * competing answer and the hive that gave it.
 *
 * The value is shown as well as the disagreement, never instead of it. The API
 * resolves several of these fields from more than one registry value name
 * (`DisplayVersion` then `ReleaseId`, `TimeZoneKeyName` then `StandardName`,
 * `CurrentBuildNumber` then `CurrentBuild`), filing a conflict for each name it
 * could not settle and still returning a value from a later name that the hives
 * agreed on. Dropping the value in that case would hide an answer the evidence
 * did give — so both are rendered, and the conflict names the value it is about.
 *
 * `conflicts` is a list for the same reason: one field can produce one conflict
 * per value name, and showing only the first would leave the page banner
 * counting disagreements the page never displays.
 */
function Fact({
  label,
  value,
  conflicts = [],
  note,
}: {
  label: string;
  value: string;
  conflicts?: SystemIdentityConflict[];
  /**
   * A sentence beneath the value. Use it for a qualification the value cannot
   * carry on its own — most of all for an absence that has a reason, since an
   * empty cell reads as a recorded blank rather than as nothing recorded.
   */
  note?: string;
}) {
  return (
    <div className="sysinfo-fact">
      <dt>{label}</dt>
      <dd className={value === MISSING ? "sysinfo-missing" : undefined}>
        {/* A bare dash beside a disagreement would still read as "the evidence
            is silent". It is not: the evidence spoke twice and contradicted
            itself, which is a different thing to write in a report. */}
        <span className="sysinfo-value">
          {value === MISSING && conflicts.length > 0 ? "not determined" : value}
        </span>
        {conflicts.map((conflict) => (
          <div
            key={`${conflict.field}:${conflict.value_name}`}
            className="sysinfo-conflict"
            role="note"
          >
            <span className="badge badge-warn" title={conflict.detail}>
              hives disagree
            </span>{" "}
            <span className="mono">{conflict.value_name}</span>
            <ul className="sysinfo-conflict-values">
              {conflict.values.map((v) => (
                <li key={`${v.hive}:${v.value}`}>
                  <span className="sysinfo-conflict-hive">{v.hive}</span>{" "}
                  <span className="mono">{v.value}</span>
                </li>
              ))}
            </ul>
            <p className="sysinfo-conflict-detail">{conflict.detail}</p>
          </div>
        ))}
        {note != null && <p className="sysinfo-fact-note">{note}</p>}
      </dd>
    </div>
  );
}

/** A titled panel wrapping a definition list. */
function Panel({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="sysinfo-panel">
      <h2>{title}</h2>
      <dl className="sysinfo-facts">{children}</dl>
    </section>
  );
}

/** A best-effort field off a USB record (shapes vary by hive). */
function usbField(d: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = d[k];
    if (typeof v === "string" && v.length) return v;
    if (typeof v === "number") return String(v);
  }
  return MISSING;
}

/**
 * The hives this case holds and the parser refused.
 *
 * Every field on this page is compiled from parsed hives, so a hive that did
 * not parse takes its facts with it silently: the OS, the computer name, the
 * timezone, the accounts all render blank, exactly as they would for a machine
 * that had none of them. Naming the refusal, with the reader's own reason, is
 * the difference between "the evidence says nothing" and "we could not read
 * the evidence" — and only the second is a lead worth following.
 */
function UnparsedHives({ hives }: { hives: UnparsedHive[] }) {
  if (hives.length === 0) return null;
  return (
    <div className="warn-note" role="note">
      <p>
        {hives.length === 1
          ? "One registry hive in this case could not be parsed, so nothing from it is compiled here. Its absence below is not evidence of absence."
          : `${hives.length} registry hives in this case could not be parsed, so nothing from them is compiled here. Their absence below is not evidence of absence.`}
      </p>
      <ul className="sysinfo-unparsed">
        {hives.map((h, i) => (
          <li key={`${h.hive}-${i}`}>
            <strong>{h.hive}</strong>
            {h.error ? <> — {h.error}</> : null}
            {h.hive_dirty ? (
              <>
                {" "}
                (never cleanly flushed
                {h.replay_reason ? `; log replay: ${h.replay_reason}` : ""})
              </>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  );
}

/** The human label for each device fact, in the product's own words. */
const DEVICE_FACT_LABEL: Record<string, string> = {
  manufacturer: "Manufacturer",
  model: "Model",
  device: "Device codename",
  product_name: "Product",
  device_name: "Device name",
  phone_number: "Phone number",
  serial_number: "Serial number",
  unique_identifier: "Unique device ID",
  imei: "IMEI",
  os_version: "OS version",
  android_version: "Android version",
  sdk_level: "SDK level",
  build_id: "Build",
  build_display_id: "Build (display)",
  build_fingerprint: "Build fingerprint",
  security_patch: "Security patch",
  build_date_utc: "Build date",
  build_type: "Build type",
  build_tags: "Build tags",
  hardware: "Hardware",
  bootloader: "Bootloader",
  cpu_abi: "CPU ABI",
  locale: "Locale",
  timezone: "Time zone",
  encryption_state: "Encryption state",
  encryption_type: "Encryption type",
  verified_boot_state: "Verified boot",
  last_backup: "Last backup",
  // A Linux host states its identity in small files of its own.
  host_name: "Host name",
  computer_name: "Computer name",
  dns_host_name: "DNS host name",
  pretty_name: "Distribution",
  os_name: "OS name",
  version_id: "OS version ID",
  codename: "Release codename",
  os_id: "OS identifier",
  os_like: "Derived from",
  variant: "Variant",
  machine_id: "Machine ID",
  user_account: "Accounts",
};

/** What to call the exhibit in a sentence about it. A laptop is not "a device
 * whose partitions disagree", and a sentence that says so sends an examiner
 * looking for partitions the evidence does not have. */
const EXHIBIT_NOUN: Record<string, string> = {
  android: "device",
  ios: "device",
  linux: "machine",
  macos: "machine",
};

/** The shape a disagreement about this kind of exhibit usually takes. */
const DISAGREEMENT_EXAMPLE: Record<string, string> = {
  android: " a device whose partitions disagree",
  ios: " a device whose partitions disagree",
  linux: " a machine whose release files disagree",
  macos: " a machine whose property lists disagree",
};

const PLATFORM_LABEL: Record<string, string> = {
  android: "Android device",
  ios: "Apple device",
  linux: "Linux machine",
  macos: "Mac",
};

/**
 * One device fact, with every reading of it and where each was read.
 *
 * A fact the sources disagree about is shown as a disagreement, not resolved:
 * a vendor image reflashed over a system image is exactly what that looks like,
 * and picking a winner would hide the one thing worth seeing. Each reading names
 * its file and the property or plist key inside it, because an examiner asked to
 * stand over "the model is Pixel 7a" has to be able to say what they read.
 */
function DeviceFactRow({ fact }: { fact: DeviceFact }) {
  const label = DEVICE_FACT_LABEL[fact.fact] ?? fact.fact.replace(/_/g, " ");
  return (
    <div className="sysinfo-fact">
      <dt>{label}</dt>
      <dd>
        {/* One value when the sources agree it is one. A fact a device can
            legitimately have several of — two SIMs, three accounts — lists them
            all; a fact that can only have one, reported two ways, is a
            disagreement and says so. */}
        {fact.agreed && !fact.multi_valued ? (
          <span className="sysinfo-value">{fact.readings[0]?.value}</span>
        ) : !fact.agreed ? (
          <span className="badge badge-warn">sources disagree</span>
        ) : null}
        {fact.readings.map((reading, i) => (
          <div
            key={`${reading.source_file}:${reading.source_key}:${i}`}
            className="sysinfo-source"
          >
            {(!fact.agreed || fact.multi_valued) && (
              <span className="sysinfo-value">{reading.value}</span>
            )}{" "}
            <span className="mono">{reading.source_file}</span>
            {reading.source_key ? (
              <>
                {" · "}
                <span className="mono">{reading.source_key}</span>
              </>
            ) : null}
          </div>
        ))}
      </dd>
    </div>
  );
}

function DeviceCard({ device }: { device: MobileDevice }) {
  return (
    <section className="sysinfo-panel sysinfo-device">
      <h2>{PLATFORM_LABEL[device.platform] ?? device.platform}</h2>
      {device.disagreements > 0 && (
        <div className="warn-note" role="note">
          {device.disagreements === 1
            ? `One fact about this ${EXHIBIT_NOUN[device.platform] ?? "device"} is`
            : `${device.disagreements} facts about this ${EXHIBIT_NOUN[device.platform] ?? "device"} are`}{" "}
          reported differently by different sources. Every reading is shown with
          the file and key it came from, and none is presented as the answer:
          {DISAGREEMENT_EXAMPLE[device.platform] ??
            " a device whose partitions disagree"}{" "}
          is a finding, not a tie to break.
        </div>
      )}
      <dl className="sysinfo-facts">
        {device.facts.map((fact) => (
          <DeviceFactRow key={fact.fact} fact={fact} />
        ))}
      </dl>
    </section>
  );
}

/**
 * The device-facts panel: "whose phone is this?" (HUNT-079).
 *
 * Renders nothing when the case holds no mobile evidence — this page's subject
 * is a Windows machine unless a phone is in the case. Compiled from the Android
 * property files and the iOS backup manifest the parsers already read; an iOS
 * backup answers it even while it is still locked, because the manifest names
 * the device in the clear.
 */
/** One query for the device facts, shared by the panel and the page around it,
 * so the page can tell whether a device was compiled without fetching twice. */
function useDeviceInfo(caseId: string | undefined, sourceId?: string) {
  return useQuery({
    queryKey: sourceId
      ? ["device-info", caseId, sourceId]
      : ["device-info", caseId],
    queryFn: () => getDeviceInfo(caseId!, sourceId),
    enabled: !!caseId,
  });
}

function MobileDevices({
  caseId,
  sourceId,
  registryNote,
}: {
  caseId: string;
  sourceId?: string;
  /** Shown under the cards when the case has no registry, so an examiner is not
   * left thinking the Windows sections were simply forgotten. */
  registryNote?: string;
}) {
  const query = useDeviceInfo(caseId, sourceId);

  if (query.isPending) return null;
  // An error is shown, never swallowed: a panel that silently disappears reads
  // as a case with no mobile evidence in it.
  if (query.isError) {
    return (
      <div className="error-note">
        Device facts could not be compiled: {(query.error as Error).message}
      </div>
    );
  }
  const info = query.data;
  if (!info.devices.length) return null;

  return (
    <>
      {info.devices.map((device) => (
        <DeviceCard key={device.platform} device={device} />
      ))}
      {registryNote && <p className="sysinfo-sub">{registryNote}</p>}
      {info.incomplete.length > 0 && (
        <div className="warn-note" role="note">
          {info.incomplete.length === 1
            ? "One source these facts were compiled from was"
            : `${info.incomplete.length} sources these facts were compiled from were`}{" "}
          not read in full, so a fact missing above may be one that was never
          reached rather than one the device did not hold:{" "}
          {info.incomplete.map((s, i) => (
            <span key={s.source_file}>
              {i > 0 ? "; " : ""}
              <span className="mono">{s.source_file}</span>
              {s.detail ? ` — ${s.detail}` : ""}
            </span>
          ))}
          .
        </div>
      )}
      {info.truncated && (
        <div className="warn-note" role="note">
          More device records exist than this panel read, so these facts are a
          subset of what the case holds.
        </div>
      )}
    </>
  );
}

/**
 * Acquisitions compiled on one page before it says it stopped.
 *
 * Each section is its own `system_info` request, and the handler's caps are
 * 200 rows x 50 pages x 3 record types = 30,000 metadata objects and 150
 * SELECTs **per section**. Ten is a real case's worth of machines and a bound
 * this page can afford; past it the page says how many it did not compile,
 * because a silent truncation here reads as "this case holds ten machines".
 */
export const MAX_SOURCE_SECTIONS = 10;

/**
 * One acquisition's compiled view.
 *
 * Split out of `SystemInfoPage` on 2026-09-15 (`ROADMAP` §2.6) so a case
 * holding two machines renders one section each instead of one merged view.
 * The merged view was not merely coarse, it was **unsafe**: the extractor
 * nulls any identity field two hives disagree about, so machine A's computer
 * name was withheld because machine B existed; where two machines
 * coincidentally agree, one value was presented as the case's answer with
 * nothing saying two machines said it; and its RegBack rule matches on hive
 * type alone, so machine A's live hive could make machine B's backup hive read
 * as "an earlier state of the same machine". Scoping each section to one
 * `source_id` puts every one of those rules back inside one acquisition, where
 * they are true.
 *
 * There is deliberately **no second API shape**: this is the same endpoint the
 * source picker already used, so there is one code path rather than two that
 * can drift.
 */
function SystemInfoForSource({
  caseId,
  activeSource,
  sourceSelector,
  sectionHeading,
}: {
  caseId: string;
  activeSource: string | undefined;
  /** Rendered in the header. Omitted on a per-acquisition section. */
  sourceSelector?: React.ReactNode;
  /** The acquisition's name, when this is one section of several. */
  sectionHeading?: string;
}) {
  const query = useQuery({
    queryKey: activeSource
      ? ["system-info", caseId, activeSource]
      : ["system-info", caseId],
    queryFn: () => getSystemInfo(caseId, activeSource),
    enabled: !!caseId,
  });

  // Whether a device card will be rendered below. Shared query, so asking costs
  // no second request.
  const devices = useDeviceInfo(caseId, activeSource);
  const compiledDevices = (devices.data?.devices.length ?? 0) > 0;

  if (query.isPending)
    return <div className="loading">Loading system info…</div>;
  if (query.isError) {
    return <div className="error-note">{(query.error as Error).message}</div>;
  }
  const info: SystemInfo = query.data;
  const conflicts = info.identity_conflicts ?? [];
  const notes = info.identity_notes ?? [];
  const controlSets = info.control_sets ?? [];
  // Keyed by the dotted field path the API files a conflict under, so each row
  // can ask whether ITS field is the disputed one. Every match is returned: the
  // API files one conflict per registry value name it could not settle, so a
  // field read from two names (`DisplayVersion` then `ReleaseId`) can carry two.
  const conflictsFor = (...fields: string[]) =>
    conflicts.filter((c) => fields.includes(c.field));
  // Whatever the rows below could not claim. A conflict filed against a field
  // this page does not render would otherwise be counted in the banner and
  // shown nowhere — the banner would promise a disagreement the examiner cannot
  // find. Listed explicitly instead, so a new field on the API side surfaces
  // rather than disappears.
  const SHOWN_FIELDS = [
    "os.product_name",
    "os.release_id",
    "os.current_version",
    "os.build",
    "os.install_date",
    "os.registered_owner",
    "os.registered_organization",
    "computer_name",
    "timezone",
    "last_shutdown",
    "last_logon_user",
    "logon_domain",
    "network_domain",
  ];
  const unshownConflicts = conflicts.filter(
    (c) => !SHOWN_FIELDS.includes(c.field),
  );

  // Hives the case holds and could not read. Naming them is what separates
  // "this machine has no registry" from "its registry would not parse"
  // (HUNT-054) — the two rendered identically, on a domain controller whose
  // SOFTWARE and SYSTEM hives were both present.
  const unparsed = info.unparsed_hives ?? [];

  if (info.hive_count === 0) {
    // A case can hold no registry and still answer "what machine is this" — a
    // phone, or a Linux box whose identity lives in /etc. "No system
    // information" printed under a card that has just named the machine
    // contradicts the panel above it, so it stands down to a note as soon as a
    // device has been compiled. If the device query itself failed, the empty
    // state stays: a page that says nothing at all is worse than one that says
    // the registry was empty.
    const registryNote = activeSource
      ? "This source has no parsed Windows registry hives, so the Windows sections of this screen have nothing to compile."
      : "No Windows registry hives were parsed in this case, so the Windows sections of this screen have nothing to compile.";
    return (
      <div
        className={
          sectionHeading != null ? "sysinfo sysinfo-section" : "sysinfo"
        }
      >
        {sectionHeading != null && (
          <h2 className="sysinfo-section-heading">{sectionHeading}</h2>
        )}
        {sourceSelector}
        <MobileDevices
          caseId={caseId}
          sourceId={activeSource}
          registryNote={registryNote}
        />
        {!compiledDevices && (
          <div className="empty-state">
            <h3>No system information</h3>
            <p>
              {registryNote} System Info is built from SOFTWARE / SYSTEM hive
              facts, and from the identity files of a phone or a Linux host.
            </p>
          </div>
        )}
        <UnparsedHives hives={unparsed} />
      </div>
    );
  }

  return (
    <div className={sectionHeading != null ? "sysinfo sysinfo-section" : "sysinfo"}>
      <header className="sysinfo-head">
        <div className="sysinfo-head-row">
          {/* A section of several names its acquisition; on its own the page
              carries its own title. Either way the heading says which machine
              the facts below belong to. */}
          {sectionHeading != null ? (
            <h2 className="sysinfo-section-heading">{sectionHeading}</h2>
          ) : (
            <h1>System Info</h1>
          )}
          {sourceSelector}
        </div>
        <p className="sysinfo-sub">
          Compiled from {info.hive_count} parsed registry{" "}
          {info.hive_count === 1 ? "hive" : "hives"}
          {activeSource ? " from this source" : ""}. Blank fields were not
          present in the evidence.
        </p>
      </header>

      <MobileDevices caseId={caseId} sourceId={activeSource} />

      <UnparsedHives hives={unparsed} />

      {/* The conflict banner. A case holding two machines' hives — or a live
          hive beside a shadow copy — can carry two answers for one identity
          field. The API refuses to pick, so this is the only place an examiner
          learns that a blank below means "the evidence contradicts itself"
          rather than "the evidence is silent". */}
      {conflicts.length > 0 && (
        <div className="warn-note" role="note">
          {conflicts.length === 1
            ? "One machine-identity field is"
            : `${conflicts.length} machine-identity fields are`}{" "}
          reported by more than one hive with different values. Every
          disagreement is shown below, with each competing answer and the hive
          that gave it, and none of the competing answers is presented as the
          answer: this case may hold hives from more than one machine, and
          attributing one machine's identity to another is not a recoverable
          error in a report.
          {unshownConflicts.length > 0 && (
            <>
              {" "}
              {unshownConflicts.length} of them{" "}
              {unshownConflicts.length === 1 ? "is" : "are"} about a field this
              page does not have a row for, so{" "}
              {unshownConflicts.length === 1 ? "it is" : "they are"} listed
              here:{" "}
              <span className="mono">
                {unshownConflicts.map((c) => c.field).join(", ")}
              </span>
              .
            </>
          )}
        </div>
      )}

      <div className="sysinfo-grid">
        <Panel title="Operating system">
          <Fact
            label="Product"
            value={val(info.os.product_name)}
            conflicts={conflictsFor("os.product_name")}
          />
          <Fact
            label="Version"
            value={val(info.os.release_id ?? info.os.current_version)}
            conflicts={conflictsFor("os.release_id", "os.current_version")}
          />
          <Fact
            label="Build"
            value={val(info.os.build)}
            conflicts={conflictsFor("os.build")}
          />
          <Fact
            label="Install date"
            value={timeVal(info.os.install_date)}
            conflicts={conflictsFor("os.install_date")}
          />
          <Fact
            label="Registered owner"
            value={val(info.os.registered_owner)}
            conflicts={conflictsFor("os.registered_owner")}
          />
          <Fact
            label="Organization"
            value={val(info.os.registered_organization)}
            conflicts={conflictsFor("os.registered_organization")}
          />
        </Panel>

        <Panel title="Machine">
          <Fact
            label="Computer name"
            value={val(info.computer_name)}
            conflicts={conflictsFor("computer_name")}
          />
          <Fact
            label="Time zone"
            value={val(info.timezone)}
            conflicts={conflictsFor("timezone")}
          />
          <Fact
            label="Last shutdown"
            value={timeVal(info.last_shutdown)}
            conflicts={conflictsFor("last_shutdown")}
          />
          {/* Winlogon's pre-filled account is the last interactive logon. The
              label says "last logon", not "last user", because the registry
              records which account the logon screen would offer next — not who
              typed the password (LIVE-029). */}
          <Fact
            label="Last interactive logon"
            value={val(info.last_logon_user)}
            conflicts={conflictsFor("last_logon_user")}
          />
          <Fact
            label="Logon domain"
            value={val(info.logon_domain)}
            conflicts={conflictsFor("logon_domain")}
          />
          <Fact
            label="Network domain"
            value={val(info.network_domain)}
            conflicts={conflictsFor("network_domain")}
          />
        </Panel>

        {/* Accounts and profiles are two populations and were shown as one
            (LIVE-029): an account that never logged on has no profile
            directory, so a machine with five local accounts read as four
            "user accounts". Both are here, each under its own name. */}
        <Panel title={`Local accounts (${(info.sam_accounts ?? []).length})`}>
          <Fact
            label="Read from"
            value="SAM — every local account the machine holds, whether or not it has ever logged on"
          />
          {info.sam_source_hives != null && info.sam_source_hives > 1 && (
            <Fact
              label="Merged from"
              value={`${info.sam_source_hives} hives — if they came from different machines this is the union of their accounts, not one machine's`}
            />
          )}
          {/* The RID, the last logon and whether the account is enabled come
              out of the SAM `F` and `V` binary values, which nothing parsed
              until ROADMAP §2.6. An account with detail is shown with it; an
              account named in the index whose own key was not read is shown as
              a name, and the note below reconciles the two counts so the
              shorter list is never read as the whole answer. */}
          {(info.sam_accounts ?? []).length === 0 ? (
            <Fact label="Accounts" value={MISSING} />
          ) : (
            (info.sam_accounts ?? []).map((a) => {
              const detail = (info.local_accounts ?? []).find(
                (d) => d.username === a,
              );
              if (!detail) return <Fact key={a} label="Account" value={a} />;
              const parts: string[] = [];
              if (detail.rid != null) parts.push(`RID ${detail.rid}`);
              if (detail.account_enabled != null) {
                parts.push(detail.account_enabled ? "enabled" : "disabled");
              }
              if (detail.login_count != null) {
                parts.push(
                  `${detail.login_count} logon${detail.login_count === 1 ? "" : "s"}`,
                );
              }
              return (
                <Fact
                  key={a}
                  label="Account"
                  value={`${a} — ${parts.join(", ")}`}
                  note={
                    // A last logon, or the sentence saying there is none. An
                    // empty cell reads as a recorded blank rather than as
                    // nothing recorded (HUNT-057).
                    detail.last_logon != null
                      ? `Last logon ${detail.last_logon}`
                      : (detail.last_logon_absent_reason ?? undefined)
                  }
                />
              );
            })
          )}
          {info.local_accounts_note != null && (
            <Fact label="Account detail" value={info.local_accounts_note} />
          )}
        </Panel>

        <Panel title={`User profiles (${info.users.length})`}>
          <Fact
            label="Read from"
            value="ProfileList — the accounts that have logged on and been given a profile directory. Fewer than the local accounts above, by design."
          />
          {/* A profile list is an inventory, not an identity, so hives add to it
              rather than contradict each other. Which means the count alone can
              read as one machine's users when it is two machines' merged. */}
          {info.profile_source_hives != null &&
            info.profile_source_hives > 1 && (
              <Fact
                label="Merged from"
                value={`${info.profile_source_hives} hives — if they came from different machines this is the union of their users, not one machine's`}
              />
            )}
          {info.users.length === 0 ? (
            <Fact label="Profiles" value={MISSING} />
          ) : (
            info.users.map((u) => <Fact key={u} label="Profile" value={u} />)
          )}
        </Panel>

        {(controlSets.length > 0 || notes.length > 0) && (
          <Panel title="How these were read">
            {/* The scoping behind every field above: a computer name left in
                ControlSet002 is not the running configuration, so the set each
                hive named is part of the answer, not a footnote. */}
            {controlSets.map((cs) => (
              <Fact
                key={`${cs.hive}:${cs.current_control_set}`}
                label={cs.hive}
                value={cs.current_control_set}
              />
            ))}
            {notes.map((note) => (
              <Fact key={note} label="Note" value={note} />
            ))}
          </Panel>
        )}
      </div>

      <section className="sysinfo-panel">
        <h2>USB device history ({info.usb_devices.length})</h2>
        {info.truncated && (
          <p className="sysinfo-missing">
            Showing a capped subset — this case has more registry/USB records
            than were compiled here.
          </p>
        )}
        {info.usb_devices.length === 0 ? (
          <p className="sysinfo-missing">
            No USBSTOR device history in the evidence.
          </p>
        ) : (
          <div className="sysinfo-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Friendly name</th>
                  <th>Vendor</th>
                  <th>Product</th>
                  <th>Serial</th>
                </tr>
              </thead>
              <tbody>
                {info.usb_devices.map((d, i) => (
                  <tr key={i} tabIndex={0}>
                    <td>{usbField(d, ["friendly_name", "name"])}</td>
                    <td>{usbField(d, ["vendor"])}</td>
                    <td>{usbField(d, ["product"])}</td>
                    <td className="mono">{usbField(d, ["serial"])}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export function SystemInfoPage() {
  const { caseId } = useParams<{ caseId: string }>();

  // Which acquisition to compile. A case can hold more than one machine's
  // registry, and a merged view answers about A machine — see
  // `SystemInfoForSource` for the three extractor rules that make the merged
  // answer wrong rather than merely coarse. So with more than one acquisition
  // and none chosen, each is compiled on its own below.
  const source = useSourceFilter(caseId);
  const sourceSelector = (
    <SourceSelect
      filter={source}
      id="sysinfo-source"
      wrapperClassName="sysinfo-source-filter"
      // It used to say "All sources (merged)", and promised a merge that is no
      // longer performed and would not be safe to perform.
      allLabel="All sources (compiled separately)"
    />
  );

  if (!caseId) return null;

  // One acquisition, or one chosen: exactly one compiled view, with the picker
  // in its header.
  if (!source.multiSource || source.activeSource) {
    return (
      <SystemInfoForSource
        caseId={caseId}
        activeSource={source.activeSource}
        sourceSelector={source.multiSource ? sourceSelector : undefined}
      />
    );
  }

  // More than one acquisition and none chosen: a section each.
  const shown = source.sourceItems.slice(0, MAX_SOURCE_SECTIONS);
  const notShown = source.sourceItems.length - shown.length;
  return (
    <div className="sysinfo-sources">
      <header className="sysinfo-head">
        <div className="sysinfo-head-row">
          <h1>System Info</h1>
          {sourceSelector}
        </div>
        <p className="sysinfo-sub">
          This case holds {source.sourceItems.length} acquisitions, and they are{" "}
          <strong>compiled separately</strong> below. A single view would have
          to answer "what machine is this" about more than one machine: where
          two disagree the answer is withheld, and where they happen to agree
          one machine's value is presented as the case's. Choose an acquisition
          above to read just that one.
        </p>
      </header>
      {shown.map((s) => (
        <SystemInfoForSource
          key={s.id}
          caseId={caseId}
          activeSource={s.id}
          sectionHeading={s.name ?? s.id}
        />
      ))}
      {notShown > 0 && (
        <div className="warn-note" role="note">
          {notShown} further {notShown === 1 ? "acquisition was" : "acquisitions were"}{" "}
          not compiled: this page renders at most {MAX_SOURCE_SECTIONS} sections,
          because each is a separate compilation over the whole of that
          acquisition's registry. Choose one above to read it. Nothing about{" "}
          {notShown === 1 ? "it" : "them"} is established either way by their
          absence here.
        </div>
      )}
    </div>
  );
}
