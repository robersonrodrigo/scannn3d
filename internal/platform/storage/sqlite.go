package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(dsn string) (*SQLiteStore, error) {
	// Enable foreign keys via connection string pragma
	db, err := sql.Open("sqlite3", dsn+"?_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	s := &SQLiteStore{db: db}
	if err := s.init(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) init() error {
	schema := `
	PRAGMA foreign_keys = ON;

	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE,
		password_hash TEXT,
		role TEXT,
		created_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS projects (
		id TEXT PRIMARY KEY,
		name TEXT UNIQUE,
		description TEXT,
		scope TEXT,
		type TEXT,
		created_by TEXT,
		created_at DATETIME,
		FOREIGN KEY(created_by) REFERENCES users(id)
	);
	CREATE TABLE IF NOT EXISTS targets (
		id TEXT PRIMARY KEY,
		address TEXT,
		created_by TEXT,
		created_at DATETIME,
		FOREIGN KEY(created_by) REFERENCES users(id)
	);
	CREATE TABLE IF NOT EXISTS scans (
		id TEXT PRIMARY KEY,
		target_id TEXT,
		mode TEXT,
		status TEXT,
		created_by TEXT,
		started_at DATETIME,
		finished_at DATETIME,
		error TEXT,
		normalized_target TEXT,
		target_type TEXT,
		profile TEXT,
		FOREIGN KEY(target_id) REFERENCES targets(id),
		FOREIGN KEY(created_by) REFERENCES users(id)
	);
	CREATE TABLE IF NOT EXISTS assets (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		host TEXT,
		ip TEXT,
		platform TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS services (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		asset_id TEXT,
		port INTEGER,
		protocol TEXT,
		name TEXT,
		banner TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS applications (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		asset_id TEXT,
		base_url TEXT,
		app_type TEXT,
		framework TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		target_id TEXT,
		asset_id TEXT,
		application_id TEXT,
		service_id TEXT,
		type TEXT,
		severity TEXT,
		cvss REAL,
		vector TEXT,
		title TEXT,
		description TEXT,
		evidence TEXT,
		recommendation TEXT,
		created_at DATETIME,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
		FOREIGN KEY(target_id) REFERENCES targets(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS graph_nodes (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		kind TEXT,
		ref_id TEXT,
		label TEXT,
		metadata TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS graph_edges (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		from_id TEXT,
		to_id TEXT,
		type TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS attack_chains (
		id TEXT PRIMARY KEY,
		scan_id TEXT,
		target TEXT,
		steps TEXT,
		summary TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	CREATE TABLE IF NOT EXISTS step_results (
		scan_id TEXT,
		name TEXT,
		status TEXT,
		summary TEXT,
		severity TEXT,
		evidence TEXT,
		details TEXT,
		started_at DATETIME,
		finished_at DATETIME,
		category TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
	);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLiteStore) CreateUser(username, passwordHash string, role Role) (User, error) {
	u := User{
		ID:           fmt.Sprintf("usr-%d", time.Now().UnixNano()),
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
		CreatedAt:    time.Now().UTC(),
	}
	_, err := s.db.Exec("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)",
		u.ID, u.Username, u.PasswordHash, string(u.Role), u.CreatedAt)
	return u, err
}

func (s *SQLiteStore) GetUser(id string) (User, bool) {
	var u User
	var role string
	err := s.db.QueryRow("SELECT id, username, password_hash, role, created_at FROM users WHERE id = ?", id).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.CreatedAt)
	if err != nil {
		return User{}, false
	}
	u.Role = Role(role)
	return u, true
}

func (s *SQLiteStore) UpdateUser(userID, username, passwordHash string, role Role) (User, error) {
	var (
		res sql.Result
		err error
	)
	if passwordHash == "" {
		res, err = s.db.Exec("UPDATE users SET username = ?, role = ? WHERE id = ?", username, string(role), userID)
	} else {
		res, err = s.db.Exec("UPDATE users SET username = ?, role = ?, password_hash = ? WHERE id = ?", username, string(role), passwordHash, userID)
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

func (s *SQLiteStore) UpdateUserPassword(userID, passwordHash string) error {
	res, err := s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", passwordHash, userID)
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

func (s *SQLiteStore) ListUsers() []User {
	rows, err := s.db.Query("SELECT id, username, role, created_at FROM users")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var role string
		rows.Scan(&u.ID, &u.Username, &role, &u.CreatedAt)
		u.Role = Role(role)
		out = append(out, u)
	}
	return out
}

func (s *SQLiteStore) GetUserByUsername(username string) (User, bool) {
	var u User
	var role string
	err := s.db.QueryRow("SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?", username).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.CreatedAt)
	if err != nil {
		return User{}, false
	}
	u.Role = Role(role)
	return u, true
}

func (s *SQLiteStore) SeedAdminIfEmpty(passwordHash string) {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count == 0 {
		s.CreateUser("admin", passwordHash, RoleAdmin)
	}
}

func (s *SQLiteStore) CreateProject(name, description string, scope []string, typ ProjectType, createdBy string) (Project, error) {
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
	_, err := s.db.Exec("INSERT INTO projects (id, name, description, scope, type, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		p.ID, p.Name, p.Description, string(scopeJSON), string(p.Type), p.CreatedBy, p.CreatedAt)
	return p, err
}

func (s *SQLiteStore) ListProjects() []Project {
	rows, err := s.db.Query("SELECT id, name, description, scope, type, created_by, created_at FROM projects ORDER BY created_at DESC")
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Project
	for rows.Next() {
		var p Project
		var scopeJSON, typ string
		rows.Scan(&p.ID, &p.Name, &p.Description, &scopeJSON, &typ, &p.CreatedBy, &p.CreatedAt)
		json.Unmarshal([]byte(scopeJSON), &p.Scope)
		p.Type = ProjectType(typ)
		out = append(out, p)
	}
	return out
}

func (s *SQLiteStore) GetProject(id string) (Project, bool) {
	var p Project
	var scopeJSON, typ string
	err := s.db.QueryRow("SELECT id, name, description, scope, type, created_by, created_at FROM projects WHERE id = ?", id).
		Scan(&p.ID, &p.Name, &p.Description, &scopeJSON, &typ, &p.CreatedBy, &p.CreatedAt)
	if err != nil {
		return Project{}, false
	}
	json.Unmarshal([]byte(scopeJSON), &p.Scope)
	p.Type = ProjectType(typ)
	return p, true
}

func (s *SQLiteStore) FindOrCreateTarget(address, createdBy string) Target {
	var t Target
	err := s.db.QueryRow("SELECT id, address, created_by, created_at FROM targets WHERE address = ?", address).
		Scan(&t.ID, &t.Address, &t.CreatedBy, &t.CreatedAt)
	if err == nil {
		return t
	}
	t = Target{ID: fmt.Sprintf("tgt-%d", time.Now().UnixNano()), Address: address, CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	s.db.Exec("INSERT INTO targets (id, address, created_by, created_at) VALUES (?, ?, ?, ?)", t.ID, t.Address, t.CreatedBy, t.CreatedAt)
	return t
}

func (s *SQLiteStore) ListTargets() []Target {
	rows, _ := s.db.Query("SELECT id, address, created_by, created_at FROM targets ORDER BY created_at DESC")
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		rows.Scan(&t.ID, &t.Address, &t.CreatedBy, &t.CreatedAt)
		out = append(out, t)
	}
	return out
}

func (s *SQLiteStore) GetTarget(id string) (Target, bool) {
	var t Target
	err := s.db.QueryRow("SELECT id, address, created_by, created_at FROM targets WHERE id = ?", id).
		Scan(&t.ID, &t.Address, &t.CreatedBy, &t.CreatedAt)
	return t, err == nil
}

func (s *SQLiteStore) CreateScan(targetID string, mode ScanMode, createdBy, normalizedTarget, targetType, profile string) Scan {
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
	s.db.Exec("INSERT INTO scans (id, target_id, mode, status, created_by, started_at, normalized_target, target_type, profile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
		sc.ID, sc.TargetID, string(sc.Mode), string(sc.Status), sc.CreatedBy, sc.StartedAt, sc.NormalizedTarget, sc.TargetType, sc.Profile)
	return sc
}

func (s *SQLiteStore) FindActiveScanByTargetMode(normalizedTarget string, mode ScanMode) (Scan, bool) {
	var sc Scan
	var status, scMode string
	err := s.db.QueryRow("SELECT id, target_id, mode, status, created_by, started_at, normalized_target, target_type, profile FROM scans WHERE normalized_target = ? AND mode = ? AND (status = 'queued' OR status = 'running')", normalizedTarget, string(mode)).
		Scan(&sc.ID, &sc.TargetID, &scMode, &status, &sc.CreatedBy, &sc.StartedAt, &sc.NormalizedTarget, &sc.TargetType, &sc.Profile)
	if err != nil {
		return Scan{}, false
	}
	sc.Status = ScanStatus(status)
	sc.Mode = ScanMode(scMode)
	return sc, true
}

func (s *SQLiteStore) UpdateScanStatus(scanID string, status ScanStatus, errMsg string) {
	finishedAt := time.Now().UTC()
	if status == ScanCompleted || status == ScanFailed {
		s.db.Exec("UPDATE scans SET status = ?, error = ?, finished_at = ? WHERE id = ?", string(status), errMsg, finishedAt, scanID)
	} else {
		s.db.Exec("UPDATE scans SET status = ?, error = ? WHERE id = ?", string(status), errMsg, scanID)
	}
}

func (s *SQLiteStore) GetScan(id string) (Scan, bool) {
	var sc Scan
	var status, mode string
	err := s.db.QueryRow("SELECT id, target_id, mode, status, created_by, started_at, finished_at, error, normalized_target, target_type, profile FROM scans WHERE id = ?", id).
		Scan(&sc.ID, &sc.TargetID, &mode, &status, &sc.CreatedBy, &sc.StartedAt, &sc.FinishedAt, &sc.Error, &sc.NormalizedTarget, &sc.TargetType, &sc.Profile)
	if err != nil {
		return Scan{}, false
	}
	sc.Status = ScanStatus(status)
	sc.Mode = ScanMode(mode)
	return sc, true
}

func (s *SQLiteStore) ListScans() []Scan {
	rows, _ := s.db.Query("SELECT id, target_id, mode, status, created_by, started_at, finished_at, error, normalized_target, target_type, profile FROM scans ORDER BY started_at DESC")
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var sc Scan
		var status, mode string
		rows.Scan(&sc.ID, &sc.TargetID, &mode, &status, &sc.CreatedBy, &sc.StartedAt, &sc.FinishedAt, &sc.Error, &sc.NormalizedTarget, &sc.TargetType, &sc.Profile)
		sc.Status = ScanStatus(status)
		sc.Mode = ScanMode(mode)
		out = append(out, sc)
	}
	return out
}

func (s *SQLiteStore) SaveVulnerabilities(scanID string, vulns []Vulnerability) {
	for _, v := range vulns {
		id := v.ID
		if id == "" {
			id = fmt.Sprintf("vuln-%d-%s", time.Now().UnixNano(), v.Type)
		}
		createdAt := v.CreatedAt
		if createdAt.IsZero() {
			createdAt = time.Now().UTC()
		}
		s.db.Exec("INSERT INTO vulnerabilities (id, scan_id, target_id, asset_id, application_id, service_id, type, severity, cvss, vector, title, description, evidence, recommendation, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			id, scanID, v.TargetID, v.AssetID, v.ApplicationID, v.ServiceID, v.Type, v.Severity, v.CVSS, v.Vector, v.Title, v.Description, v.Evidence, v.Recommendation, createdAt)
	}
}

func (s *SQLiteStore) ListVulnerabilities() []Vulnerability {
	rows, _ := s.db.Query("SELECT id, scan_id, target_id, asset_id, application_id, service_id, type, severity, cvss, vector, title, description, evidence, recommendation, created_at FROM vulnerabilities ORDER BY created_at DESC")
	defer rows.Close()
	var out []Vulnerability
	for rows.Next() {
		var v Vulnerability
		rows.Scan(&v.ID, &v.ScanID, &v.TargetID, &v.AssetID, &v.ApplicationID, &v.ServiceID, &v.Type, &v.Severity, &v.CVSS, &v.Vector, &v.Title, &v.Description, &v.Evidence, &v.Recommendation, &v.CreatedAt)
		out = append(out, v)
	}
	return out
}

func (s *SQLiteStore) SaveAssets(scanID string, assets []Asset) {
	for _, a := range assets {
		id := a.ID
		if id == "" {
			id = fmt.Sprintf("ast-%d", time.Now().UnixNano())
		}
		s.db.Exec("INSERT INTO assets (id, scan_id, host, ip, platform) VALUES (?, ?, ?, ?, ?)",
			id, scanID, a.Host, a.IP, a.Platform)
	}
}

func (s *SQLiteStore) SaveServices(scanID string, services []Service) {
	for _, sv := range services {
		id := sv.ID
		if id == "" {
			id = fmt.Sprintf("svc-%d", time.Now().UnixNano())
		}
		s.db.Exec("INSERT INTO services (id, scan_id, asset_id, port, protocol, name, banner) VALUES (?, ?, ?, ?, ?, ?, ?)",
			id, scanID, sv.AssetID, sv.Port, sv.Protocol, sv.Name, sv.Banner)
	}
}

func (s *SQLiteStore) SaveApplications(scanID string, apps []Application) {
	for _, a := range apps {
		id := a.ID
		if id == "" {
			id = fmt.Sprintf("app-%d", time.Now().UnixNano())
		}
		s.db.Exec("INSERT INTO applications (id, scan_id, asset_id, base_url, app_type, framework) VALUES (?, ?, ?, ?, ?, ?)",
			id, scanID, a.AssetID, a.BaseURL, a.AppType, a.Framework)
	}
}

func (s *SQLiteStore) SaveGraph(scanID string, nodes []GraphNode, edges []GraphEdge) {
	for _, n := range nodes {
		meta, _ := json.Marshal(n.Metadata)
		s.db.Exec("INSERT INTO graph_nodes (id, scan_id, kind, ref_id, label, metadata) VALUES (?, ?, ?, ?, ?, ?)",
			n.ID, scanID, n.Kind, n.RefID, n.Label, string(meta))
	}
	for _, e := range edges {
		s.db.Exec("INSERT INTO graph_edges (id, scan_id, from_id, to_id, type) VALUES (?, ?, ?, ?, ?)",
			e.ID, scanID, e.FromID, e.ToID, e.Type)
	}
}

func (s *SQLiteStore) SaveAttackChain(scanID string, chain AttackChain) {
	steps, _ := json.Marshal(chain.Steps)
	id := chain.ID
	if id == "" {
		id = fmt.Sprintf("chn-%d", time.Now().UnixNano())
	}
	s.db.Exec("INSERT INTO attack_chains (id, scan_id, target, steps, summary) VALUES (?, ?, ?, ?, ?)",
		id, scanID, chain.Target, string(steps), chain.Summary)
}

func (s *SQLiteStore) SaveStepResults(scanID string, steps []ScanStepResult) {
	for _, st := range steps {
		details, _ := json.Marshal(st.Details)
		s.db.Exec("INSERT INTO step_results (scan_id, name, status, summary, severity, evidence, details, started_at, finished_at, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
			scanID, st.Name, st.Status, st.Summary, st.Severity, st.Evidence, string(details), st.StartedAt, st.FinishedAt, st.Category)
	}
}

func (s *SQLiteStore) BuildScanBundle(scanID string) (ScanBundle, bool) {
	sc, ok := s.GetScan(scanID)
	if !ok {
		return ScanBundle{}, false
	}
	t, _ := s.GetTarget(sc.TargetID)

	bundle := ScanBundle{Scan: sc, Target: t}

	// Assets
	aRows, _ := s.db.Query("SELECT id, scan_id, host, ip, platform FROM assets WHERE scan_id = ?", scanID)
	for aRows.Next() {
		var a Asset
		aRows.Scan(&a.ID, &a.ScanID, &a.Host, &a.IP, &a.Platform)
		bundle.Assets = append(bundle.Assets, a)
	}
	aRows.Close()

	// Services
	sRows, _ := s.db.Query("SELECT id, scan_id, asset_id, port, protocol, name, banner FROM services WHERE scan_id = ?", scanID)
	for sRows.Next() {
		var sv Service
		sRows.Scan(&sv.ID, &sv.ScanID, &sv.AssetID, &sv.Port, &sv.Protocol, &sv.Name, &sv.Banner)
		bundle.Services = append(bundle.Services, sv)
	}
	sRows.Close()

	// Applications
	appRows, _ := s.db.Query("SELECT id, scan_id, asset_id, base_url, app_type, framework FROM applications WHERE scan_id = ?", scanID)
	for appRows.Next() {
		var app Application
		appRows.Scan(&app.ID, &app.ScanID, &app.AssetID, &app.BaseURL, &app.AppType, &app.Framework)
		bundle.Applications = append(bundle.Applications, app)
	}
	appRows.Close()

	// Vulnerabilities
	vRows, _ := s.db.Query("SELECT id, scan_id, target_id, asset_id, application_id, service_id, type, severity, cvss, vector, title, description, evidence, recommendation, created_at FROM vulnerabilities WHERE scan_id = ?", scanID)
	for vRows.Next() {
		var v Vulnerability
		vRows.Scan(&v.ID, &v.ScanID, &v.TargetID, &v.AssetID, &v.ApplicationID, &v.ServiceID, &v.Type, &v.Severity, &v.CVSS, &v.Vector, &v.Title, &v.Description, &v.Evidence, &v.Recommendation, &v.CreatedAt)
		bundle.Vulnerabilities = append(bundle.Vulnerabilities, v)
	}
	vRows.Close()

	// Graph Nodes
	gnRows, _ := s.db.Query("SELECT id, scan_id, kind, ref_id, label, metadata FROM graph_nodes WHERE scan_id = ?", scanID)
	for gnRows.Next() {
		var gn GraphNode
		var meta string
		gnRows.Scan(&gn.ID, &gn.ScanID, &gn.Kind, &gn.RefID, &gn.Label, &meta)
		json.Unmarshal([]byte(meta), &gn.Metadata)
		bundle.GraphNodes = append(bundle.GraphNodes, gn)
	}
	gnRows.Close()

	// Graph Edges
	geRows, _ := s.db.Query("SELECT id, scan_id, from_id, to_id, type FROM graph_edges WHERE scan_id = ?", scanID)
	for geRows.Next() {
		var ge GraphEdge
		geRows.Scan(&ge.ID, &ge.ScanID, &ge.FromID, &ge.ToID, &ge.Type)
		bundle.GraphEdges = append(bundle.GraphEdges, ge)
	}
	geRows.Close()

	// Attack Chain
	var chain AttackChain
	var steps string
	err := s.db.QueryRow("SELECT id, scan_id, target, steps, summary FROM attack_chains WHERE scan_id = ?", scanID).
		Scan(&chain.ID, &chain.ScanID, &chain.Target, &steps, &chain.Summary)
	if err == nil {
		json.Unmarshal([]byte(steps), &chain.Steps)
		bundle.AttackChain = chain
	}

	// Step Results
	srRows, _ := s.db.Query("SELECT name, status, summary, severity, evidence, details, started_at, finished_at, category FROM step_results WHERE scan_id = ?", scanID)
	for srRows.Next() {
		var sr ScanStepResult
		var details string
		srRows.Scan(&sr.Name, &sr.Status, &sr.Summary, &sr.Severity, &sr.Evidence, &details, &sr.StartedAt, &sr.FinishedAt, &sr.Category)
		json.Unmarshal([]byte(details), &sr.Details)
		bundle.StepResults = append(bundle.StepResults, sr)
	}
	srRows.Close()

	return bundle, true
}

// Implementação parcial para demonstração - em um cenário real completaria todos os métodos da interface Store.
// Para manter a compatibilidade com a interface atual do Store (que é uma struct, não interface), precisaremos refatorar.
