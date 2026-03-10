package storage

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Store interface {
	CreateUser(username, passwordHash string, role Role) (User, error)
	GetUserByUsername(username string) (User, bool)
	GetUser(id string) (User, bool)
	UpdateUser(userID, username, passwordHash string, role Role) (User, error)
	UpdateUserPassword(userID, passwordHash string) error
	ListUsers() []User
	SeedAdminIfEmpty(passwordHash string)

	CreateProject(name, description string, scope []string, typ ProjectType, createdBy string) (Project, error)
	ListProjects() []Project
	GetProject(id string) (Project, bool)

	FindOrCreateTarget(address, createdBy string) Target
	ListTargets() []Target
	GetTarget(id string) (Target, bool)

	CreateScan(targetID string, mode ScanMode, createdBy, normalizedTarget, targetType, profile string) Scan
	FindActiveScanByTargetMode(normalizedTarget string, mode ScanMode) (Scan, bool)
	UpdateScanStatus(scanID string, status ScanStatus, errMsg string)
	GetScan(id string) (Scan, bool)
	ListScans() []Scan

	SaveAssets(scanID string, assets []Asset)
	SaveServices(scanID string, services []Service)
	SaveApplications(scanID string, apps []Application)
	SaveVulnerabilities(scanID string, vulns []Vulnerability)
	SaveGraph(scanID string, nodes []GraphNode, edges []GraphEdge)
	SaveAttackChain(scanID string, chain AttackChain)
	SaveStepResults(scanID string, steps []ScanStepResult)

	ListVulnerabilities() []Vulnerability
	BuildScanBundle(scanID string) (ScanBundle, bool)
}

type InMemoryStore struct {
	mu sync.RWMutex

	users           map[string]User
	usersByName     map[string]string
	projects        map[string]Project
	projectsByName  map[string]string
	targets         map[string]Target
	scans           map[string]Scan
	assets          map[string][]Asset
	services        map[string][]Service
	applications    map[string][]Application
	vulnerabilities map[string][]Vulnerability
	graphNodes      map[string][]GraphNode
	graphEdges      map[string][]GraphEdge
	attackChains    map[string]AttackChain
	stepResults     map[string][]ScanStepResult

	seq atomic.Uint64
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		users:           map[string]User{},
		usersByName:     map[string]string{},
		projects:        map[string]Project{},
		projectsByName:  map[string]string{},
		targets:         map[string]Target{},
		scans:           map[string]Scan{},
		assets:          map[string][]Asset{},
		services:        map[string][]Service{},
		applications:    map[string][]Application{},
		vulnerabilities: map[string][]Vulnerability{},
		graphNodes:      map[string][]GraphNode{},
		graphEdges:      map[string][]GraphEdge{},
		attackChains:    map[string]AttackChain{},
		stepResults:     map[string][]ScanStepResult{},
	}
}

func (s *InMemoryStore) nextID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, s.seq.Add(1))
}

func (s *InMemoryStore) CreateUser(username, passwordHash string, role Role) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.usersByName[username]; ok {
		return User{}, errors.New("user already exists")
	}
	u := User{ID: s.nextID("usr"), Username: username, PasswordHash: passwordHash, Role: role, CreatedAt: time.Now().UTC()}
	s.users[u.ID] = u
	s.usersByName[username] = u.ID
	return u, nil
}

func (s *InMemoryStore) GetUserByUsername(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.usersByName[username]
	if !ok {
		return User{}, false
	}
	u, ok := s.users[id]
	return u, ok
}

func (s *InMemoryStore) GetUser(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[id]
	return u, ok
}

func (s *InMemoryStore) UpdateUser(userID, username, passwordHash string, role Role) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.users[userID]
	if !ok {
		return User{}, errors.New("user not found")
	}
	if existingID, exists := s.usersByName[username]; exists && existingID != userID {
		return User{}, errors.New("user already exists")
	}
	if u.Username != username {
		delete(s.usersByName, u.Username)
		s.usersByName[username] = userID
		u.Username = username
	}
	u.Role = role
	if passwordHash != "" {
		u.PasswordHash = passwordHash
	}
	s.users[userID] = u
	return u, nil
}

func (s *InMemoryStore) UpdateUserPassword(userID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[userID]
	if !ok {
		return errors.New("user not found")
	}
	u.PasswordHash = passwordHash
	s.users[userID] = u
	return nil
}

func (s *InMemoryStore) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *InMemoryStore) SeedAdminIfEmpty(passwordHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) > 0 {
		return
	}
	u := User{ID: s.nextID("usr"), Username: "admin", PasswordHash: passwordHash, Role: RoleAdmin, CreatedAt: time.Now().UTC()}
	s.users[u.ID] = u
	s.usersByName[u.Username] = u.ID
}

func (s *InMemoryStore) CreateProject(name, description string, scope []string, typ ProjectType, createdBy string) (Project, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normalizeKey(name)
	if key == "" {
		return Project{}, errors.New("project name is required")
	}
	if _, ok := s.projectsByName[key]; ok {
		return Project{}, errors.New("project already exists")
	}
	if len(scope) == 0 {
		return Project{}, errors.New("project scope is required")
	}
	p := Project{
		ID:          s.nextID("prj"),
		Name:        name,
		Description: description,
		Scope:       append([]string(nil), scope...),
		Type:        typ,
		CreatedBy:   createdBy,
		CreatedAt:   time.Now().UTC(),
	}
	s.projects[p.ID] = p
	s.projectsByName[key] = p.ID
	return p, nil
}

func (s *InMemoryStore) ListProjects() []Project {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Project, 0, len(s.projects))
	for _, p := range s.projects {
		cp := p
		cp.Scope = append([]string(nil), p.Scope...)
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *InMemoryStore) GetProject(id string) (Project, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.projects[id]
	if !ok {
		return Project{}, false
	}
	cp := p
	cp.Scope = append([]string(nil), p.Scope...)
	return cp, true
}

func (s *InMemoryStore) FindOrCreateTarget(address, createdBy string) Target {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.targets {
		if t.Address == address {
			return t
		}
	}
	t := Target{ID: s.nextID("tgt"), Address: address, CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	s.targets[t.ID] = t
	return t
}

func (s *InMemoryStore) ListTargets() []Target {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Target, 0, len(s.targets))
	for _, t := range s.targets {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *InMemoryStore) GetTarget(id string) (Target, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.targets[id]
	return t, ok
}

func (s *InMemoryStore) CreateScan(targetID string, mode ScanMode, createdBy, normalizedTarget, targetType, profile string) Scan {
	s.mu.Lock()
	defer s.mu.Unlock()
	scan := Scan{
		ID:               s.nextID("scan"),
		TargetID:         targetID,
		Mode:             mode,
		Status:           ScanQueued,
		CreatedBy:        createdBy,
		StartedAt:        time.Now().UTC(),
		NormalizedTarget: normalizedTarget,
		TargetType:       targetType,
		Profile:          profile,
	}
	s.scans[scan.ID] = scan
	return scan
}

func (s *InMemoryStore) FindActiveScanByTargetMode(normalizedTarget string, mode ScanMode) (Scan, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sc := range s.scans {
		if sc.NormalizedTarget != normalizedTarget {
			continue
		}
		if sc.Mode != mode {
			continue
		}
		if sc.Status == ScanQueued || sc.Status == ScanRunning {
			return sc, true
		}
	}
	return Scan{}, false
}

func (s *InMemoryStore) UpdateScanStatus(scanID string, status ScanStatus, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	scan, ok := s.scans[scanID]
	if !ok {
		return
	}
	scan.Status = status
	scan.Error = errMsg
	if status == ScanCompleted || status == ScanFailed {
		scan.FinishedAt = time.Now().UTC()
	}
	s.scans[scanID] = scan
}

func (s *InMemoryStore) GetScan(id string) (Scan, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scan, ok := s.scans[id]
	return scan, ok
}

func (s *InMemoryStore) ListScans() []Scan {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Scan, 0, len(s.scans))
	for _, sc := range s.scans {
		out = append(out, sc)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

func (s *InMemoryStore) SaveAssets(scanID string, assets []Asset) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range assets {
		if assets[i].ID == "" {
			assets[i].ID = s.nextID("ast")
		}
		assets[i].ScanID = scanID
	}
	s.assets[scanID] = assets
}

func (s *InMemoryStore) SaveServices(scanID string, services []Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range services {
		if services[i].ID == "" {
			services[i].ID = s.nextID("svc")
		}
		services[i].ScanID = scanID
	}
	s.services[scanID] = services
}

func (s *InMemoryStore) SaveApplications(scanID string, apps []Application) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range apps {
		if apps[i].ID == "" {
			apps[i].ID = s.nextID("app")
		}
		apps[i].ScanID = scanID
	}
	s.applications[scanID] = apps
}

func (s *InMemoryStore) SaveVulnerabilities(scanID string, vulns []Vulnerability) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range vulns {
		if vulns[i].ID == "" {
			vulns[i].ID = s.nextID("vuln")
		}
		vulns[i].ScanID = scanID
		if vulns[i].CreatedAt.IsZero() {
			vulns[i].CreatedAt = time.Now().UTC()
		}
	}
	s.vulnerabilities[scanID] = vulns
}

func (s *InMemoryStore) SaveGraph(scanID string, nodes []GraphNode, edges []GraphEdge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range nodes {
		if nodes[i].ID == "" {
			nodes[i].ID = s.nextID("node")
		}
		nodes[i].ScanID = scanID
	}
	for i := range edges {
		if edges[i].ID == "" {
			edges[i].ID = s.nextID("edge")
		}
		edges[i].ScanID = scanID
	}
	s.graphNodes[scanID] = nodes
	s.graphEdges[scanID] = edges
}

func (s *InMemoryStore) SaveAttackChain(scanID string, chain AttackChain) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if chain.ID == "" {
		chain.ID = s.nextID("chain")
	}
	chain.ScanID = scanID
	s.attackChains[scanID] = chain
}

func (s *InMemoryStore) SaveStepResults(scanID string, steps []ScanStepResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range steps {
		if steps[i].StartedAt.IsZero() {
			steps[i].StartedAt = time.Now().UTC()
		}
		if steps[i].FinishedAt.IsZero() {
			steps[i].FinishedAt = time.Now().UTC()
		}
	}
	s.stepResults[scanID] = append([]ScanStepResult(nil), steps...)
}

func (s *InMemoryStore) ListVulnerabilities() []Vulnerability {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Vulnerability, 0)
	for _, vv := range s.vulnerabilities {
		out = append(out, vv...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (s *InMemoryStore) BuildScanBundle(scanID string) (ScanBundle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scan, ok := s.scans[scanID]
	if !ok {
		return ScanBundle{}, false
	}
	target := s.targets[scan.TargetID]
	bundle := ScanBundle{
		Scan:            scan,
		Target:          target,
		Assets:          cloneAssets(s.assets[scanID]),
		Services:        cloneServices(s.services[scanID]),
		Applications:    cloneApps(s.applications[scanID]),
		Vulnerabilities: cloneVulns(s.vulnerabilities[scanID]),
		GraphNodes:      cloneNodes(s.graphNodes[scanID]),
		GraphEdges:      cloneEdges(s.graphEdges[scanID]),
		AttackChain:     s.attackChains[scanID],
		StepResults:     cloneSteps(s.stepResults[scanID]),
	}
	return bundle, true
}

func cloneAssets(in []Asset) []Asset { out := make([]Asset, len(in)); copy(out, in); return out }
func cloneServices(in []Service) []Service {
	out := make([]Service, len(in))
	copy(out, in)
	return out
}
func cloneApps(in []Application) []Application {
	out := make([]Application, len(in))
	copy(out, in)
	return out
}
func cloneVulns(in []Vulnerability) []Vulnerability {
	out := make([]Vulnerability, len(in))
	copy(out, in)
	return out
}
func cloneNodes(in []GraphNode) []GraphNode {
	out := make([]GraphNode, len(in))
	copy(out, in)
	return out
}
func cloneEdges(in []GraphEdge) []GraphEdge {
	out := make([]GraphEdge, len(in))
	copy(out, in)
	return out
}
func cloneSteps(in []ScanStepResult) []ScanStepResult {
	out := make([]ScanStepResult, len(in))
	copy(out, in)
	return out
}

func normalizeKey(in string) string {
	return strings.ToLower(strings.TrimSpace(in))
}
