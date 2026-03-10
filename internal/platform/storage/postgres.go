package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	// Safe defaults for high-concurrency scan workloads.
	db.SetMaxOpenConns(40)
	db.SetMaxIdleConns(20)
	db.SetConnMaxLifetime(30 * time.Minute)

	s := &PostgresStore{db: db}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *PostgresStore) init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL
	);

	CREATE TABLE IF NOT EXISTS projects (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE NOT NULL,
		description TEXT NOT NULL DEFAULT '',
		scope TEXT NOT NULL,
		type TEXT NOT NULL,
		created_by TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		FOREIGN KEY(created_by) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS targets (
		id TEXT PRIMARY KEY,
		address TEXT NOT NULL UNIQUE,
		created_by TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		FOREIGN KEY(created_by) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target_id TEXT NOT NULL,
		mode TEXT NOT NULL,
		status TEXT NOT NULL,
		created_by TEXT NOT NULL,
		started_at TIMESTAMPTZ NOT NULL,
		finished_at TIMESTAMPTZ,
		error TEXT NOT NULL DEFAULT '',
		normalized_target TEXT NOT NULL DEFAULT '',
		target_type TEXT NOT NULL DEFAULT '',
		profile TEXT NOT NULL DEFAULT '',
		FOREIGN KEY(target_id) REFERENCES targets(id),
		FOREIGN KEY(created_by) REFERENCES users(id)
	);

	CREATE TABLE IF NOT EXISTS assets (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		host TEXT NOT NULL,
		ip TEXT NOT NULL DEFAULT '',
		platform TEXT NOT NULL DEFAULT '',
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS services (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		asset_id TEXT,
		port INTEGER NOT NULL,
		protocol TEXT NOT NULL,
		name TEXT NOT NULL DEFAULT '',
		banner TEXT NOT NULL DEFAULT '',
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL
	);

	CREATE TABLE IF NOT EXISTS applications (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		asset_id TEXT,
		base_url TEXT NOT NULL,
		app_type TEXT NOT NULL DEFAULT '',
		framework TEXT NOT NULL DEFAULT '',
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL
	);

	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		target_id TEXT NOT NULL,
		asset_id TEXT,
		application_id TEXT,
		service_id TEXT,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		cvss DOUBLE PRECISION NOT NULL DEFAULT 0,
		vector TEXT NOT NULL DEFAULT '',
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		evidence TEXT NOT NULL,
		recommendation TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE,
		FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE SET NULL,
		FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE SET NULL,
		FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE SET NULL
	);

	CREATE TABLE IF NOT EXISTS graph_nodes (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		kind TEXT NOT NULL,
		ref_id TEXT NOT NULL,
		label TEXT NOT NULL,
		metadata TEXT NOT NULL DEFAULT '{}',
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS graph_edges (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		from_id TEXT NOT NULL,
		to_id TEXT NOT NULL,
		type TEXT NOT NULL,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS attack_chains (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		target TEXT NOT NULL,
		steps TEXT NOT NULL,
		summary TEXT NOT NULL,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS step_results (
		scan_id TEXT NOT NULL,
		name TEXT NOT NULL,
		status TEXT NOT NULL,
		summary TEXT NOT NULL DEFAULT '',
		severity TEXT NOT NULL DEFAULT '',
		evidence TEXT NOT NULL DEFAULT '',
		details TEXT NOT NULL DEFAULT '{}',
		started_at TIMESTAMPTZ,
		finished_at TIMESTAMPTZ,
		category TEXT NOT NULL DEFAULT '',
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_scans_started_at ON scans(started_at DESC);
	CREATE INDEX IF NOT EXISTS idx_scans_target_id ON scans(target_id, started_at DESC);
	CREATE INDEX IF NOT EXISTS idx_scans_target_mode_status ON scans(normalized_target, mode, status);
	CREATE INDEX IF NOT EXISTS idx_vulns_scan_id ON vulnerabilities(scan_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_vulns_target_sev ON vulnerabilities(target_id, severity, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_assets_scan_id ON assets(scan_id);
	CREATE INDEX IF NOT EXISTS idx_services_scan_id ON services(scan_id);
	CREATE INDEX IF NOT EXISTS idx_apps_scan_id ON applications(scan_id);
	CREATE INDEX IF NOT EXISTS idx_steps_scan_id ON step_results(scan_id);
	CREATE INDEX IF NOT EXISTS idx_graph_nodes_scan_id ON graph_nodes(scan_id);
	CREATE INDEX IF NOT EXISTS idx_graph_edges_scan_id ON graph_edges(scan_id);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *PostgresStore) exec(query string, args ...any) (sql.Result, error) {
	return s.db.Exec(rebindPostgres(query), args...)
}

func (s *PostgresStore) query(query string, args ...any) (*sql.Rows, error) {
	return s.db.Query(rebindPostgres(query), args...)
}

func (s *PostgresStore) queryRow(query string, args ...any) *sql.Row {
	return s.db.QueryRow(rebindPostgres(query), args...)
}

func rebindPostgres(query string) string {
	if !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 1
	for _, r := range query {
		if r == '?' {
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			n++
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func nullableString(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func (s *PostgresStore) CreateUser(username, passwordHash string, role Role) (User, error) {
	u := User{
		ID:           fmt.Sprintf("usr-%d", time.Now().UnixNano()),
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}
	_, err := s.exec("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
		u.ID, u.Username, u.PasswordHash, string(u.Role), u.CreatedAt)
	return u, err
}

func (s *PostgresStore) GetUser(id string) (User, bool) {
	var u User
	var role string
	err := s.queryRow("SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?", id).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.CreatedAt)
	if err != nil {
		return User{}, false
	}
	u.Role = Role(role)
	return u, true
}

func (s *PostgresStore) UpdateUser(userID, username, passwordHash string, role Role) (User, error) {
	var (
		res sql.Result
		err error
	)
	if passwordHash == "" {
		res, err = s.exec("UPDATE users SET username = ?, role = ? WHERE id = ?", username, string(role), userID)
	} else {
		res, err = s.exec("UPDATE users SET username = ?, role = ?, password_hash = ? WHERE id = ?", username, string(role), passwordHash, userID)
	}
	if err != nil {
		return User{}, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return User{}, err
	}
	if affected == 0 {
		return User{}, errors.New("user not found")
	}
	u, ok := s.GetUser(userID)
	if !ok {
		return User{}, errors.New("user not found")
	}
	return u, nil
}

func (s *PostgresStore) UpdateUserPassword(userID, passwordHash string) error {
	res, err := s.exec("UPDATE users SET password_hash = ? WHERE id = ?", passwordHash, userID)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errors.New("user not found")
	}
	return nil
}

func (s *PostgresStore) ListUsers() []User {
	rows, err := s.query("SELECT id, username, role, created_at FROM users")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var role string
		_ = rows.Scan(&u.ID, &u.Username, &role, &u.CreatedAt)
		u.Role = Role(role)
		out = append(out, u)
	}
	return out
}

func (s *PostgresStore) GetUserByUsername(username string) (User, bool) {
	var u User
	var role string
	err := s.queryRow("SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?", username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.CreatedAt)
	if err != nil {
		return User{}, false
	}
	u.Role = Role(role)
	return u, true
}

func (s *PostgresStore) SeedAdminIfEmpty(passwordHash string) {
	var count int
	_ = s.queryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		_, _ = s.CreateUser("admin", passwordHash, RoleAdmin)
	}
}

func (s *PostgresStore) CreateProject(name, description string, scope []string, typ ProjectType, createdBy string) (Project, error) {
	scopeJSON, _ := json.Marshal(scope)
	p := Project{
		ID:          fmt.Sprintf("prj-%d", time.Now().UnixNano()),
		Name:        name,
		Description: description,
		Scope:       scope,
		Type:        typ,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now().UTC(),
	}
	_, err := s.exec("INSERT INTO projects (id, name, description, scope, type, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		p.ID, p.Name, p.Description, string(scopeJSON), string(p.Type), p.CreatedBy, p.CreatedAt)
	return p, err
}

func (s *PostgresStore) ListProjects() []Project {
	rows, err := s.query("SELECT id, name, description, scope, type, created_by, created_at FROM projects ORDER BY created_at DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		var scopeJSON, typ string
		_ = rows.Scan(&p.ID, &p.Name, &p.Description, &scopeJSON, &typ, &p.CreatedBy, &p.CreatedAt)
		_ = json.Unmarshal([]byte(scopeJSON), &p.Scope)
		p.Type = ProjectType(typ)
		out = append(out, p)
	}
	return out
}

func (s *PostgresStore) GetProject(id string) (Project, bool) {
	var p Project
	var scopeJSON, typ string
	err := s.queryRow("SELECT id, name, description, scope, type, created_by, created_at FROM projects WHERE id = ?", id).
		Scan(&p.ID, &p.Name, &p.Description, &scopeJSON, &typ, &p.CreatedBy, &p.CreatedAt)
	if err != nil {
		return Project{}, false
	}
	_ = json.Unmarshal([]byte(scopeJSON), &p.Scope)
	p.Type = ProjectType(typ)
	return p, true
}

func (s *PostgresStore) FindOrCreateTarget(address, createdBy string) Target {
	var t Target
	err := s.queryRow("SELECT id, address, created_by, created_at FROM targets WHERE address = ?", address).
		Scan(&t.ID, &t.Address, &t.CreatedBy, &t.CreatedAt)
	if err == nil {
		return t
	}
	t = Target{ID: fmt.Sprintf("tgt-%d", time.Now().UnixNano()), Address: address, CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	_, _ = s.exec("INSERT INTO targets (id, address, created_by, created_at) VALUES (?, ?, ?, ?)", t.ID, t.Address, t.CreatedBy, t.CreatedAt)
	return t
}

func (s *PostgresStore) ListTargets() []Target {
	rows, err := s.query("SELECT id, address, created_by, created_at FROM targets ORDER BY created_at DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		_ = rows.Scan(&t.ID, &t.Address, &t.CreatedBy, &t.CreatedAt)
		out = append(out, t)
	}
	return out
}

func (s *PostgresStore) GetTarget(id string) (Target, bool) {
	var t Target
	err := s.queryRow("SELECT id, address, created_by, created_at FROM targets WHERE id = ?", id).
		Scan(&t.ID, &t.Address, &t.CreatedBy, &t.CreatedAt)
	return t, err == nil
}

func (s *PostgresStore) CreateScan(targetID string, mode ScanMode, createdBy, normalizedTarget, targetType, profile string) Scan {
	sc := Scan{
		ID:               fmt.Sprintf("scan-%d", time.Now().UnixNano()),
		TargetID:         targetID,
		Mode:             mode,
		Status:           ScanQueued,
		CreatedBy:        createdBy,
		StartedAt:        time.Now().UTC(),
		NormalizedTarget: normalizedTarget,
		TargetType:       targetType,
		Profile:          profile,
	}
	_, _ = s.exec("INSERT INTO scans (id, target_id, mode, status, created_by, started_at, normalized_target, target_type, profile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		sc.ID, sc.TargetID, string(sc.Mode), string(sc.Status), sc.CreatedBy, sc.StartedAt, sc.NormalizedTarget, sc.TargetType, sc.Profile)
	return sc
}

func (s *PostgresStore) FindActiveScanByTargetMode(normalizedTarget string, mode ScanMode) (Scan, bool) {
	var sc Scan
	var status, scMode string
	err := s.queryRow("SELECT id, target_id, mode, status, created_by, started_at, normalized_target, target_type, profile FROM scans WHERE normalized_target = ? AND mode = ? AND (status = 'queued' OR status = 'running')", normalizedTarget, string(mode)).
		Scan(&sc.ID, &sc.TargetID, &scMode, &status, &sc.CreatedBy, &sc.StartedAt, &sc.NormalizedTarget, &sc.TargetType, &sc.Profile)
	if err != nil {
		return Scan{}, false
	}
	sc.Status = ScanStatus(status)
	sc.Mode = ScanMode(scMode)
	return sc, true
}

func (s *PostgresStore) UpdateScanStatus(scanID string, status ScanStatus, errMsg string) {
	finishedAt := time.Now().UTC()
	if status == ScanCompleted || status == ScanFailed {
		_, _ = s.exec("UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE id = ?", string(status), errMsg, finishedAt, scanID)
	} else {
		_, _ = s.exec("UPDATE scans SET status = ?, error = ? WHERE id = ?", string(status), errMsg, scanID)
	}
}

func (s *PostgresStore) GetScan(id string) (Scan, bool) {
	var sc Scan
	var status, mode string
	var finished sql.NullTime
	err := s.queryRow("SELECT id, target_id, mode, status, created_by, started_at, finished_at, error, normalized_target, target_type, profile FROM scans WHERE id = ?", id).
		Scan(&sc.ID, &sc.TargetID, &mode, &status, &sc.CreatedBy, &sc.StartedAt, &finished, &sc.Error, &sc.NormalizedTarget, &sc.TargetType, &sc.Profile)
	if err != nil {
		return Scan{}, false
	}
	if finished.Valid {
		sc.FinishedAt = finished.Time
	}
	sc.Status = ScanStatus(status)
	sc.Mode = ScanMode(mode)
	return sc, true
}

func (s *PostgresStore) ListScans() []Scan {
	rows, err := s.query("SELECT id, target_id, mode, status, created_by, started_at, finished_at, error, normalized_target, target_type, profile FROM scans ORDER BY started_at DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var sc Scan
		var status, mode string
		var finished sql.NullTime
		_ = rows.Scan(&sc.ID, &sc.TargetID, &mode, &status, &sc.CreatedBy, &sc.StartedAt, &finished, &sc.Error, &sc.NormalizedTarget, &sc.TargetType, &sc.Profile)
		if finished.Valid {
			sc.FinishedAt = finished.Time
		}
		sc.Status = ScanStatus(status)
		sc.Mode = ScanMode(mode)
		out = append(out, sc)
	}
	return out
}

func (s *PostgresStore) SaveVulnerabilities(scanID string, vulns []Vulnerability) {
	for _, v := range vulns {
		id := v.ID
		if id == "" {
			id = fmt.Sprintf("vuln-%d-%s", time.Now().UnixNano(), v.Type)
		}
		createdAt := v.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		_, _ = s.exec("INSERT INTO vulnerabilities (id, scan_id, target_id, asset_id, application_id, service_id, type, severity, cvss, vector, title, description, evidence, recommendation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			id, scanID, v.TargetID, nullableString(v.AssetID), nullableString(v.ApplicationID), nullableString(v.ServiceID), v.Type, v.Severity, v.CVSS, v.Vector, v.Title, v.Description, v.Evidence, v.Recommendation, createdAt)
	}
}

func (s *PostgresStore) ListVulnerabilities() []Vulnerability {
	rows, err := s.query("SELECT id, scan_id, target_id, asset_id, application_id, service_id, type, severity, cvss, vector, title, description, evidence, recommendation, created_at FROM vulnerabilities ORDER BY created_at DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var assetID, appID, serviceID sql.NullString
		_ = rows.Scan(&v.ID, &v.ScanID, &v.TargetID, &assetID, &appID, &serviceID, &v.Type, &v.Severity, &v.CVSS, &v.Vector, &v.Title, &v.Description, &v.Evidence, &v.Recommendation, &v.CreatedAt)
		if assetID.Valid {
			v.AssetID = assetID.String
		}
		if appID.Valid {
			v.ApplicationID = appID.String
		}
		if serviceID.Valid {
			v.ServiceID = serviceID.String
		}
		out = append(out, v)
	}
	return out
}

func (s *PostgresStore) SaveAssets(scanID string, assets []Asset) {
	for _, a := range assets {
		id := a.ID
		if id == "" {
			id = fmt.Sprintf("ast-%d", time.Now().UnixNano())
		}
		_, _ = s.exec("INSERT INTO assets (id, scan_id, host, ip, platform) VALUES (?, ?, ?, ?, ?)",
			id, scanID, a.Host, a.IP, a.Platform)
	}
}

func (s *PostgresStore) SaveServices(scanID string, services []Service) {
	for _, sv := range services {
		id := sv.ID
		if id == "" {
			id = fmt.Sprintf("svc-%d", time.Now().UnixNano())
		}
		_, _ = s.exec("INSERT INTO services (id, scan_id, asset_id, port, protocol, name, banner) VALUES (?, ?, ?, ?, ?, ?, ?)",
			id, scanID, nullableString(sv.AssetID), sv.Port, sv.Protocol, sv.Name, sv.Banner)
	}
}

func (s *PostgresStore) SaveApplications(scanID string, apps []Application) {
	for _, a := range apps {
		id := a.ID
		if id == "" {
			id = fmt.Sprintf("app-%d", time.Now().UnixNano())
		}
		_, _ = s.exec("INSERT INTO applications (id, scan_id, asset_id, base_url, app_type, framework) VALUES (?, ?, ?, ?, ?, ?)",
			id, scanID, nullableString(a.AssetID), a.BaseURL, a.AppType, a.Framework)
	}
}

func (s *PostgresStore) SaveGraph(scanID string, nodes []GraphNode, edges []GraphEdge) {
	for _, n := range nodes {
		meta, _ := json.Marshal(n.Metadata)
		_, _ = s.exec("INSERT INTO graph_nodes (id, scan_id, kind, ref_id, label, metadata) VALUES (?, ?, ?, ?, ?, ?)",
			n.ID, scanID, n.Kind, n.RefID, n.Label, string(meta))
	}
	for _, e := range edges {
		_, _ = s.exec("INSERT INTO graph_edges (id, scan_id, from_id, to_id, type) VALUES (?, ?, ?, ?, ?)",
			e.ID, scanID, e.FromID, e.ToID, e.Type)
	}
}

func (s *PostgresStore) SaveAttackChain(scanID string, chain AttackChain) {
	steps, _ := json.Marshal(chain.Steps)
	id := chain.ID
	if id == "" {
		id = fmt.Sprintf("chn-%d", time.Now().UnixNano())
	}
	_, _ = s.exec("INSERT INTO attack_chains (id, scan_id, target, steps, summary) VALUES (?, ?, ?, ?, ?)",
		id, scanID, chain.Target, string(steps), chain.Summary)
}

func (s *PostgresStore) SaveStepResults(scanID string, steps []ScanStepResult) {
	for _, st := range steps {
		details, _ := json.Marshal(st.Details)
		_, _ = s.exec("INSERT INTO step_results (scan_id, name, status, summary, severity, evidence, details, started_at, finished_at, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			scanID, st.Name, st.Status, st.Summary, st.Severity, st.Evidence, string(details), nullableTime(st.StartedAt), nullableTime(st.FinishedAt), st.Category)
	}
}

func nullableTime(v time.Time) any {
	if v.IsZero() {
		return nil
	}
	return v
}

func (s *PostgresStore) BuildScanBundle(scanID string) (ScanBundle, bool) {
	sc, ok := s.GetScan(scanID)
	if !ok {
		return ScanBundle{}, false
	}
	t, _ := s.GetTarget(sc.TargetID)

	bundle := ScanBundle{Scan: sc, Target: t}

	aRows, err := s.query("SELECT id, scan_id, host, ip, platform FROM assets WHERE scan_id = ?", scanID)
	if err == nil {
		for aRows.Next() {
			var a Asset
			_ = aRows.Scan(&a.ID, &a.ScanID, &a.Host, &a.IP, &a.Platform)
			bundle.Assets = append(bundle.Assets, a)
		}
		aRows.Close()
	}

	sRows, err := s.query("SELECT id, scan_id, asset_id, port, protocol, name, banner FROM services WHERE scan_id = ?", scanID)
	if err == nil {
		for sRows.Next() {
			var sv Service
			var assetID sql.NullString
			_ = sRows.Scan(&sv.ID, &sv.ScanID, &assetID, &sv.Port, &sv.Protocol, &sv.Name, &sv.Banner)
			if assetID.Valid {
				sv.AssetID = assetID.String
			}
			bundle.Services = append(bundle.Services, sv)
		}
		sRows.Close()
	}

	appRows, err := s.query("SELECT id, scan_id, asset_id, base_url, app_type, framework FROM applications WHERE scan_id = ?", scanID)
	if err == nil {
		for appRows.Next() {
			var app Application
			var assetID sql.NullString
			_ = appRows.Scan(&app.ID, &app.ScanID, &assetID, &app.BaseURL, &app.AppType, &app.Framework)
			if assetID.Valid {
				app.AssetID = assetID.String
			}
			bundle.Applications = append(bundle.Applications, app)
		}
		appRows.Close()
	}

	vRows, err := s.query("SELECT id, scan_id, target_id, asset_id, application_id, service_id, type, severity, cvss, vector, title, description, evidence, recommendation, created_at FROM vulnerabilities WHERE scan_id = ?", scanID)
	if err == nil {
		for vRows.Next() {
			var v Vulnerability
			var assetID, appID, serviceID sql.NullString
			_ = vRows.Scan(&v.ID, &v.ScanID, &v.TargetID, &assetID, &appID, &serviceID, &v.Type, &v.Severity, &v.CVSS, &v.Vector, &v.Title, &v.Description, &v.Evidence, &v.Recommendation, &v.CreatedAt)
			if assetID.Valid {
				v.AssetID = assetID.String
			}
			if appID.Valid {
				v.ApplicationID = appID.String
			}
			if serviceID.Valid {
				v.ServiceID = serviceID.String
			}
			bundle.Vulnerabilities = append(bundle.Vulnerabilities, v)
		}
		vRows.Close()
	}

	gnRows, err := s.query("SELECT id, scan_id, kind, ref_id, label, metadata FROM graph_nodes WHERE scan_id = ?", scanID)
	if err == nil {
		for gnRows.Next() {
			var gn GraphNode
			var meta string
			_ = gnRows.Scan(&gn.ID, &gn.ScanID, &gn.Kind, &gn.RefID, &gn.Label, &meta)
			_ = json.Unmarshal([]byte(meta), &gn.Metadata)
			bundle.GraphNodes = append(bundle.GraphNodes, gn)
		}
		gnRows.Close()
	}

	geRows, err := s.query("SELECT id, scan_id, from_id, to_id, type FROM graph_edges WHERE scan_id = ?", scanID)
	if err == nil {
		for geRows.Next() {
			var ge GraphEdge
			_ = geRows.Scan(&ge.ID, &ge.ScanID, &ge.FromID, &ge.ToID, &ge.Type)
			bundle.GraphEdges = append(bundle.GraphEdges, ge)
		}
		geRows.Close()
	}

	var chain AttackChain
	var steps string
	err = s.queryRow("SELECT id, scan_id, target, steps, summary FROM attack_chains WHERE scan_id = ?", scanID).
		Scan(&chain.ID, &chain.ScanID, &chain.Target, &steps, &chain.Summary)
	if err == nil {
		_ = json.Unmarshal([]byte(steps), &chain.Steps)
		bundle.AttackChain = chain
	}

	srRows, err := s.query("SELECT name, status, summary, severity, evidence, details, started_at, finished_at, category FROM step_results WHERE scan_id = ?", scanID)
	if err == nil {
		for srRows.Next() {
			var sr ScanStepResult
			var details string
			var started, finished sql.NullTime
			_ = srRows.Scan(&sr.Name, &sr.Status, &sr.Summary, &sr.Severity, &sr.Evidence, &details, &started, &finished, &sr.Category)
			if started.Valid {
				sr.StartedAt = started.Time
			}
			if finished.Valid {
				sr.FinishedAt = finished.Time
			}
			_ = json.Unmarshal([]byte(details), &sr.Details)
			bundle.StepResults = append(bundle.StepResults, sr)
		}
		srRows.Close()
	}

	return bundle, true
}
