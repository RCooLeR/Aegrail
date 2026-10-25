import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Eye, Loader2, XCircle } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { RuleDefinition } from "../../types";
import { EmptyState, InlineAlert, Panel, ResponsiveTable, SeverityPill, StatusPill } from "../components/common";
import { issueStatusLabel, nodeLabel } from "../model/viewModels";
import type { IssueQueuePageSize, IssueRow } from "../types";
import { formatRelative } from "../utils/time";

const issueQueuePageSizes: IssueQueuePageSize[] = [25, 50, 100, 250, 500, "all"];
const virtualIssueRowHeight = 96;
const virtualIssueOverscan = 8;

export function IssuesPage({
  actionLoading,
  error,
  issueRows,
  loadedCount,
  loading,
  matchedTotal,
  matchedTotalExact,
  onNext,
  onPrevious,
  onIssue,
  onBulkStatus,
  onPageSize,
  onStatus,
  onStatusFilter,
  page,
  pageCount,
  pageSize,
  queueKey,
  ruleByID,
  selectedIssue,
  status
}: {
  actionLoading: boolean;
  error: string;
  issueRows: IssueRow[];
  loadedCount: number;
  loading: boolean;
  matchedTotal: number;
  matchedTotalExact: boolean;
  onNext: () => Promise<void>;
  onPrevious: () => void;
  onIssue: (row: IssueRow) => void;
  onBulkStatus: (rows: IssueRow[], status: string) => Promise<void>;
  onPageSize: (pageSize: IssueQueuePageSize) => void;
  onStatus: (row: IssueRow, status: string) => void;
  onStatusFilter: (status: string) => void;
  page: number;
  pageCount: number;
  pageSize: IssueQueuePageSize;
  queueKey: string;
  ruleByID: Map<string, RuleDefinition>;
  selectedIssue?: IssueRow;
  status: string;
}) {
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(() => new Set());
  const showAll = pageSize === "all";
  const selectedRows = useMemo(
    () => issueRows.filter((row) => selectedKeys.has(issueRowKey(row))),
    [issueRows, selectedKeys]
  );
  const allVisibleSelected = !showAll && issueRows.length > 0 && issueRows.every((row) => selectedKeys.has(issueRowKey(row)));
  const firstMatch = issueRows.length > 0 ? (showAll ? 1 : page * pageSize + 1) : 0;
  const lastMatch = issueRows.length > 0 ? firstMatch + issueRows.length - 1 : 0;

  useEffect(() => {
    setSelectedKeys(new Set());
  }, [page, queueKey]);

  function toggleRow(row: IssueRow, checked: boolean) {
    setSelectedKeys((current) => {
      const next = new Set(current);
      const key = issueRowKey(row);
      if (checked) {
        next.add(key);
      } else {
        next.delete(key);
      }
      return next;
    });
  }

  function toggleVisible(checked: boolean) {
    if (showAll) {
      return;
    }
    setSelectedKeys((current) => {
      const next = new Set(current);
      for (const row of issueRows) {
        const key = issueRowKey(row);
        if (checked) {
          next.add(key);
        } else {
          next.delete(key);
        }
      }
      return next;
    });
  }

  async function handleBulkStatus(nextStatus: string) {
    try {
      await onBulkStatus(selectedRows, nextStatus);
      setSelectedKeys(new Set());
    } catch {
      // The controller already exposes the error in the global action banner.
    }
  }

  const tableProps: IssueQueueTableProps = {
    actionLoading,
    allVisibleSelected,
    issueRows,
    loading,
    onIssue,
    onStatus,
    onToggleRow: toggleRow,
    onToggleVisible: toggleVisible,
    ruleByID,
    selectedIssue,
    selectedKeys,
    selectAllEnabled: !showAll
  };

  return (
    <section className="issue-queue">
      <Panel
        title="Issue queue"
        icon={AlertTriangle}
        action={(
          <div className="issue-queue-controls">
            <label>
              <span>Status</span>
              <select value={status} onChange={(event) => onStatusFilter(event.target.value)}>
                <option value="open">New only</option>
                <option value="all">All statuses</option>
                <option value="acknowledged">Acknowledged</option>
                <option value="resolved">Fixed</option>
                <option value="false_positive">False positive</option>
              </select>
            </label>
            <label>
              <span>Per page</span>
              <select
                aria-label="Issues per page"
                value={pageSize}
                onChange={(event) => onPageSize(parseIssueQueuePageSize(event.target.value))}
              >
                {issueQueuePageSizes.map((value) => (
                  <option key={value} value={value}>{value === "all" ? "Show all" : value}</option>
                ))}
              </select>
            </label>
          </div>
        )}
      >
        {error && <InlineAlert message={error} />}
        {showAll && loading && (
          <div className="issue-load-progress" aria-live="polite">
            <Loader2 size={15} className="spin" />
            <span>{matchedTotalExact
              ? `Loading all issues: ${loadedCount} of ${matchedTotal}`
              : `Loading all issues: ${loadedCount} loaded`}</span>
            {matchedTotalExact && matchedTotal > 0 && (
              <progress max={matchedTotal} value={Math.min(loadedCount, matchedTotal)} />
            )}
            <small>Changing the filter or page size cancels this load.</small>
          </div>
        )}
        <div className="bulk-action-bar">
          <span>{selectedRows.length} selected</span>
          <button className="ghost-button compact" type="button" disabled={actionLoading || selectedRows.length === 0} onClick={() => void handleBulkStatus("acknowledged")}>
            {actionLoading ? <Loader2 size={14} className="spin" /> : <Eye size={14} />}
            Acknowledge
          </button>
          <button className="ghost-button compact" type="button" disabled={actionLoading || selectedRows.length === 0} onClick={() => void handleBulkStatus("resolved")}>
            <CheckCircle2 size={14} />
            Fixed
          </button>
          <button className="ghost-button compact" type="button" disabled={actionLoading || selectedRows.length === 0} onClick={() => void handleBulkStatus("false_positive")}>
            <XCircle size={14} />
            False positive
          </button>
          {selectedRows.length > 0 && (
            <button className="link-button" type="button" disabled={actionLoading} onClick={() => setSelectedKeys(new Set())}>
              Clear
            </button>
          )}
          {showAll && <small className="bulk-selection-note">Select-all is disabled in Show all mode; individual selection remains available.</small>}
        </div>
        {showAll
          ? <VirtualizedIssueQueueTable {...tableProps} resetKey={queueKey} />
          : <StandardIssueQueueTable {...tableProps} />}
        <div className="issue-pagination" aria-label="Issue pagination">
          <span>{issueRangeLabel(showAll, loading, loadedCount, firstMatch, lastMatch, matchedTotal, matchedTotalExact)}</span>
          {showAll ? (
            <div><span>{loading ? "Loading all matches" : "All matches"}</span></div>
          ) : (
            <div>
              <button
                className="ghost-button compact"
                type="button"
                disabled={page === 0 || loading}
                onClick={onPrevious}
              >
                <ChevronLeft size={14} /> Previous
              </button>
              <span>{matchedTotalExact && matchedTotal === 0 ? "No pages" : `Page ${page + 1} of ${pageCount}`}</span>
              <button
                className="ghost-button compact"
                type="button"
                disabled={loading || !matchedTotalExact || page >= pageCount - 1}
                onClick={() => void onNext()}
              >
                {loading ? <Loader2 size={14} className="spin" /> : null}
                Next <ChevronRight size={14} />
              </button>
            </div>
          )}
        </div>
      </Panel>
    </section>
  );
}

type IssueQueueTableProps = {
  actionLoading: boolean;
  allVisibleSelected: boolean;
  issueRows: IssueRow[];
  loading: boolean;
  onIssue: (row: IssueRow) => void;
  onStatus: (row: IssueRow, status: string) => void;
  onToggleRow: (row: IssueRow, checked: boolean) => void;
  onToggleVisible: (checked: boolean) => void;
  ruleByID: Map<string, RuleDefinition>;
  selectedIssue?: IssueRow;
  selectedKeys: Set<string>;
  selectAllEnabled: boolean;
};

function StandardIssueQueueTable(props: IssueQueueTableProps) {
  return (
    <ResponsiveTable>
      <IssueTableHead {...props} />
      <tbody>
        {props.issueRows.map((row) => <IssueTableRow key={issueRowKey(row)} {...props} row={row} />)}
        {props.issueRows.length === 0 && <IssueTableEmpty loading={props.loading} />}
      </tbody>
    </ResponsiveTable>
  );
}

function VirtualizedIssueQueueTable(props: IssueQueueTableProps & { resetKey: string }) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const viewportHeight = scrollRef.current?.clientHeight ?? 640;
  const visibleCapacity = Math.ceil(viewportHeight / virtualIssueRowHeight) + virtualIssueOverscan * 2;
  const rawStart = Math.max(0, Math.floor(scrollTop / virtualIssueRowHeight) - virtualIssueOverscan);
  const start = Math.min(rawStart, Math.max(0, props.issueRows.length - visibleCapacity));
  const end = Math.min(props.issueRows.length, start + visibleCapacity);
  const visibleRows = props.issueRows.slice(start, end);
  const topSpace = start * virtualIssueRowHeight;
  const bottomSpace = Math.max(0, (props.issueRows.length - end) * virtualIssueRowHeight);

  useEffect(() => {
    setScrollTop(0);
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [props.resetKey]);

  return (
    <div
      aria-busy={props.loading}
      aria-label="All matching issues"
      className="table-wrap issue-virtual-scroll"
      onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
      ref={scrollRef}
      role="region"
      tabIndex={0}
    >
      <table>
        <IssueTableHead {...props} />
        <tbody>
          {topSpace > 0 && <VirtualSpacer height={topSpace} />}
          {visibleRows.map((row) => <IssueTableRow key={issueRowKey(row)} {...props} row={row} virtual />)}
          {bottomSpace > 0 && <VirtualSpacer height={bottomSpace} />}
          {props.issueRows.length === 0 && <IssueTableEmpty loading={props.loading} />}
        </tbody>
      </table>
    </div>
  );
}

function IssueTableHead({ allVisibleSelected, issueRows, onToggleVisible, selectAllEnabled }: IssueQueueTableProps) {
  return (
    <thead>
      <tr>
        <th className="select-cell">
          <input
            aria-label={selectAllEnabled ? "Select all visible issues" : "Select all is disabled in Show all mode"}
            checked={selectAllEnabled && allVisibleSelected}
            disabled={!selectAllEnabled || issueRows.length === 0}
            onChange={(event) => onToggleVisible(event.target.checked)}
            title={selectAllEnabled ? undefined : "Select-all is disabled in Show all mode"}
            type="checkbox"
          />
        </th>
        <th>Severity</th>
        <th>Issue</th>
        <th>Company</th>
        <th>Site</th>
        <th>Node</th>
        <th>Service</th>
        <th>Status</th>
        <th>Last seen</th>
      </tr>
    </thead>
  );
}

function IssueTableRow({
  actionLoading,
  onIssue,
  onStatus,
  onToggleRow,
  row,
  ruleByID,
  selectedIssue,
  selectedKeys,
  virtual = false
}: IssueQueueTableProps & { row: IssueRow; virtual?: boolean }) {
  return (
    <tr
      className={`${selectedIssue?.finding.id === row.finding.id ? "selected" : ""}${virtual ? " issue-virtual-row" : ""}`.trim()}
      onClick={() => onIssue(row)}
    >
      <td className="select-cell" onClick={(event) => event.stopPropagation()}>
        <input
          aria-label={`Select ${row.finding.title}`}
          checked={selectedKeys.has(issueRowKey(row))}
          onChange={(event) => onToggleRow(row, event.target.checked)}
          type="checkbox"
        />
      </td>
      <td><SeverityPill value={row.finding.severity} /></td>
      <td><strong>{row.finding.title}</strong><small>{ruleByID.get(row.finding.rule_id)?.category ?? row.finding.rule_id}</small></td>
      <td>{row.instance.companyName}</td>
      <td>{row.instance.projectName}</td>
      <td>{nodeLabel(row.instance)}</td>
      <td>{row.service}</td>
      <td>
        <StatusPill value={issueStatusLabel(row.finding.status, row.finding.status_reason)} />
        <div className="inline-row-actions">
          <button type="button" disabled={actionLoading} onClick={(event) => { event.stopPropagation(); onStatus(row, "acknowledged"); }}>Acknowledge</button>
          <button type="button" disabled={actionLoading} onClick={(event) => { event.stopPropagation(); onStatus(row, "resolved"); }}>Fixed</button>
        </div>
      </td>
      <td>{formatRelative(row.finding.last_event_at)}</td>
    </tr>
  );
}

function IssueTableEmpty({ loading }: { loading: boolean }) {
  return (
    <tr><td colSpan={9}><EmptyState title={loading ? "Loading matching issues…" : "No issues match"} /></td></tr>
  );
}

function VirtualSpacer({ height }: { height: number }) {
  return <tr aria-hidden="true" className="issue-virtual-spacer"><td colSpan={9} style={{ height }} /></tr>;
}

function issueRangeLabel(
  showAll: boolean,
  loading: boolean,
  loadedCount: number,
  firstMatch: number,
  lastMatch: number,
  matchedTotal: number,
  matchedTotalExact: boolean
) {
  if (showAll) {
    if (loading) {
      return matchedTotalExact
        ? `Loading ${loadedCount} of ${matchedTotal} matching issues`
        : `Loading all matching issues (${loadedCount} loaded)`;
    }
    if (matchedTotalExact) {
      return matchedTotal > 0 ? `Showing all ${matchedTotal} matching issues` : "No matching issues";
    }
    return `${lastMatch} matching issues loaded; exact total unavailable`;
  }
  if (!matchedTotalExact) {
    return "Exact matching issue total unavailable";
  }
  return matchedTotal > 0
    ? `Showing ${firstMatch}-${lastMatch} of ${matchedTotal} matching issues`
    : "No matching issues";
}

function parseIssueQueuePageSize(value: string): IssueQueuePageSize {
  if (value === "all") {
    return "all";
  }
  const parsed = Number(value);
  return parsed === 25 || parsed === 50 || parsed === 100 || parsed === 250 || parsed === 500 ? parsed : 50;
}

function issueRowKey(row: IssueRow) {
  return `${row.instance.key}:${row.finding.id}`;
}
