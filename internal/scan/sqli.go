package scan

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type sqliCheck struct{}

func (sqliCheck) ID() string         { return "sqli" }
func (sqliCheck) Name() string       { return "SQL injection" }
func (sqliCheck) Category() Category { return CategorySQLi }

// sqlErrorSignatures are lower-case fragments that databases print when a
// query is malformed. Each one is specific enough that finding it in a
// response which did not contain it beforehand is a strong signal.
var sqlErrorSignatures = []string{
	// MySQL / MariaDB
	"you have an error in your sql syntax",
	"warning: mysql_",
	"mysql_fetch",
	"mysql_num_rows",
	"mysqli_sql_exception",
	"mysqli_::",
	"supplied argument is not a valid mysql",
	"check the manual that corresponds to your mysql",
	// PostgreSQL
	"unterminated quoted string at or near",
	"pg_query(",
	"pg_exec(",
	"postgresql query failed",
	"pgstmtexception",
	"pg_stmt",
	"nontext error message from driver",
	// Microsoft SQL Server
	"microsoft ole db provider for sql server",
	"unclosed quotation mark after the character string",
	"incorrect syntax near",
	"mssql_query(",
	"odbc sql server driver",
	"system.data.sqlclient.sqlexception",
	"microsoft sql server native client",
	// Oracle
	"ora-01756",
	"ora-00933",
	"ora-00921",
	"ora-00942",
	"quoted string not properly terminated",
	"oracle error",
	// SQLite
	"sqlite/jdbcdriver",
	"sqlite3.operationalerror",
	"sqlite_error",
	"sqlite exception",
	"sqllogicerror",
	"sqlite3::",
	// Generic / other engines
	"sql state:",
	"sqlstate[",
	"sql syntax",
	"sql command not properly ended",
	"unexpected end of command in",
	"sql error",
	"database error",
	"db2 sql error",
	"jdbc.sqlsyntax",
	"pl/sql",
	"warning: oci",
	"microsoft jet database engine",
	"adodb.command error",
	"uncaught pdoexception",
	"pdoexception",
	"query failed",
	"sql statement",
	"syntax error at or near",
	"quoted string not terminated",
}

func (sqliCheck) Run(ctx context.Context, t *Target) ([]Finding, error) {
	page, err := t.Get(ctx, t.URL.String(), false)
	if err != nil {
		return nil, err
	}
	baseline := strings.ToLower(page.BodyString())
	baselineLen := len(page.Body)

	vectors := CollectVectors(page, t.Opts.Deep)
	if len(vectors) == 0 {
		f := Finding{
			Severity:    SeverityInfo,
			Title:       "No user input found on this page to probe for SQL injection",
			URL:         page.URL,
			Evidence:    "No query parameters and no form fields were discovered.",
			Remediation: "Probe routes that accept identifiers, filters, sorting or search terms directly.",
		}
		Emit(ctx, f)
		return []Finding{f}, nil
	}
	if len(vectors) > maxVectors {
		vectors = vectors[:maxVectors]
	}

	// Latency baseline used by the time-based probes.
	baselineRTT := page.Duration

	var mu sync.Mutex
	var out []Finding

	tasks := make([]func(), 0, len(vectors))
	for i, v := range vectors {
		v := v
		deep := t.Opts.Deep && i < 5
		tasks = append(tasks, func() {
			var found Finding
			if f, ok := errorBased(ctx, t, v, baseline, page.StatusCode); ok {
				found = f
			} else if deep {
				if f, ok := booleanBased(ctx, t, v, baselineLen); ok {
					found = f
				} else if f, ok := timeBased(ctx, t, v, baselineRTT); ok {
					found = f
				}
			}
			if found.Title == "" {
				return
			}
			Emit(ctx, found)
			mu.Lock()
			out = append(out, found)
			mu.Unlock()
		})
	}
	parallel(t.Opts.Concurrency, tasks)

	return out, nil
}

// errorBased appends quote characters and looks for a database error that
// was not present in the baseline response.
func errorBased(ctx context.Context, t *Target, v Vector, baseline string, baselineStatus int) (Finding, bool) {
	for _, suffix := range []string{"'", `"`} {
		resp, err := t.sendVector(ctx, v, v.Value+suffix)
		if err != nil {
			continue
		}
		lower := strings.ToLower(resp.BodyString())
		for _, sig := range sqlErrorSignatures {
			if strings.Contains(lower, sig) && !strings.Contains(baseline, sig) {
				return Finding{
					Severity: SeverityHigh,
					Title:    fmt.Sprintf("SQL injection via %s input %q (database error)", v.Kind, v.Name),
					URL:      resp.URL,
					Evidence: fmt.Sprintf("Appending %q to the value of %q produced a database error: %q. Status %d, baseline status %d.", suffix, v.Name, sig, resp.StatusCode, baselineStatus),
					Remediation: "Use parameterised queries / prepared statements for every database access, and map database errors to generic " +
						"client messages so internals are never echoed back.",
				}, true
			}
		}
		if resp.StatusCode >= 500 && baselineStatus < 500 {
			return Finding{
				Severity: SeverityLow,
				Title:    fmt.Sprintf("Input %q triggers a server error when malformed", v.Name),
				URL:      resp.URL,
				Evidence: fmt.Sprintf("Appending %q changed the status from %d to %d, suggesting the value reaches a query or template unescaped.", suffix, baselineStatus, resp.StatusCode),
				Remediation: "Confirm whether the value reaches a database query. Even when it is not injectable, unhandled 500s leak stack traces " +
					"and should be replaced with a generic error page.",
			}, true
		}
	}
	return Finding{}, false
}

// booleanBased compares page length under a true and a false condition.
// A matching true branch plus a changed false branch is the classic blind
// SQL injection signature.
func booleanBased(ctx context.Context, t *Target, v Vector, baselineLen int) (Finding, bool) {
	if baselineLen == 0 {
		return Finding{}, false
	}
	variants := [][2]string{
		{v.Value + "' AND '1'='1", v.Value + "' AND '1'='2"},
		{v.Value + " AND 1=1", v.Value + " AND 1=2"},
	}
	for _, pair := range variants {
		tResp, err := t.sendVector(ctx, v, pair[0])
		if err != nil {
			continue
		}
		fResp, err := t.sendVector(ctx, v, pair[1])
		if err != nil {
			continue
		}
		if tResp.StatusCode != fResp.StatusCode && fResp.StatusCode >= 500 {
			continue // noisy error page, not a boolean oracle
		}
		trueSame := relativeDelta(len(tResp.Body), baselineLen) <= 0.05
		falsediff := relativeDelta(len(fResp.Body), baselineLen) >= 0.10
		if trueSame && falsediff {
			return Finding{
				Severity: SeverityHigh,
				Title:    fmt.Sprintf("Blind (boolean) SQL injection via %s input %q", v.Kind, v.Name),
				URL:      tResp.URL,
				Evidence: fmt.Sprintf("Baseline %d bytes; AND 1=1 returned %d bytes (%.1f%% delta); AND 1=2 returned %d bytes (%.1f%% delta). The response flips with the condition.", baselineLen, len(tResp.Body), relativeDelta(len(tResp.Body), baselineLen)*100, len(fResp.Body), relativeDelta(len(fResp.Body), baselineLen)*100),
				Remediation: "Use parameterised queries. As a defence in depth measure, return a constant response shape for both outcomes " +
					"so true/false conditions cannot be observed.",
			}, true
		}
	}
	return Finding{}, false
}

// timeBased sleeps the database and measures whether the request took
// noticeably longer than the baseline round trip.
func timeBased(ctx context.Context, t *Target, v Vector, baselineRTT time.Duration) (Finding, bool) {
	if baselineRTT <= 0 {
		// No usable baseline yet; take one sample of the untouched input.
		base, err := t.sendVector(ctx, v, v.Value)
		if err != nil {
			return Finding{}, false
		}
		baselineRTT = base.Duration
	}
	if baselineRTT <= 0 {
		baselineRTT = 50 * time.Millisecond
	}
	probes := []struct{ suffix, engine string }{
		{"' AND SLEEP(3)-- ", "MySQL"},
		{"'; WAITFOR DELAY '0:0:3'-- ", "Microsoft SQL Server"},
		{"' AND pg_sleep(3)-- ", "PostgreSQL"},
	}
	for _, p := range probes {
		resp, err := t.sendVector(ctx, v, v.Value+p.suffix)
		if err != nil {
			continue
		}
		if resp.Duration >= baselineRTT+2500*time.Millisecond && resp.Duration >= 3*time.Second {
			return Finding{
				Severity:    SeverityHigh,
				Title:       fmt.Sprintf("Time-based blind SQL injection via %s input %q (%s)", v.Kind, v.Name, p.engine),
				URL:         resp.URL,
				Evidence:    fmt.Sprintf("Baseline round trip %s; payload %q took %s.", baselineRTT.Round(time.Millisecond), strings.TrimSpace(p.suffix), resp.Duration.Round(time.Millisecond)),
				Remediation: "Use parameterised queries. Time-based oracles work even when errors are hidden, so input validation alone will not stop this.",
			}, true
		}
	}
	return Finding{}, false
}
