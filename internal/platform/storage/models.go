package storage

import "time"

type Role string

const (
	RoleAdmin   Role = "admin"
	RoleAnalyst Role = "analyst"
	RoleViewer  Role = "viewer"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`
	Role         Role      `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

type Target struct {
	ID        string    `json:"id"`
	Address   string    `json:"address"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

type ProjectType string

const (
	ProjectWeb       ProjectType = "web"
	ProjectAPI       ProjectType = "api"
	ProjectBugBounty ProjectType = "bug_bounty"
	ProjectCTF       ProjectType = "ctf"
)

type Project struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Scope       []string    `json:"scope"`
	Type        ProjectType `json:"type"`
	CreatedBy   string      `json:"created_by"`
	CreatedAt   time.Time   `json:"created_at"`
}

type ScanMode string

const (
	ScanInfra ScanMode = "infra"
	ScanWeb   ScanMode = "web"
	ScanFull  ScanMode = "full"
)

type ScanStatus string

const (
	ScanQueued    ScanStatus = "queued"
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
)

type Scan struct {
	ID               string     `json:"id"`
	TargetID         string     `json:"target_id"`
	Mode             ScanMode   `json:"mode"`
	Status           ScanStatus `json:"status"`
	CreatedBy        string     `json:"created_by"`
	StartedAt        time.Time  `json:"started_at"`
	FinishedAt       time.Time  `json:"finished_at,omitempty"`
	Error            string     `json:"error,omitempty"`
	NormalizedTarget string     `json:"normalized_target,omitempty"`
	TargetType       string     `json:"target_type,omitempty"`
	Profile          string     `json:"profile,omitempty"`
}

type Asset struct {
	ID       string `json:"id"`
	ScanID   string `json:"scan_id"`
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Platform string `json:"platform,omitempty"`
}

type Service struct {
	ID       string `json:"id"`
	ScanID   string `json:"scan_id"`
	AssetID  string `json:"asset_id"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Name     string `json:"name,omitempty"`
	Banner   string `json:"banner,omitempty"`
}

type Application struct {
	ID        string `json:"id"`
	ScanID    string `json:"scan_id"`
	AssetID   string `json:"asset_id"`
	BaseURL   string `json:"base_url"`
	AppType   string `json:"app_type,omitempty"`
	Framework string `json:"framework,omitempty"`
}

type Vulnerability struct {
	ID             string    `json:"id"`
	ScanID         string    `json:"scan_id"`
	TargetID       string    `json:"target_id"`
	AssetID        string    `json:"asset_id,omitempty"`
	ApplicationID  string    `json:"application_id,omitempty"`
	ServiceID      string    `json:"service_id,omitempty"`
	Type           string    `json:"type"`
	Severity       string    `json:"severity"`
	CVSS           float64   `json:"cvss,omitempty"`
	Vector         string    `json:"vector,omitempty"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Evidence       string    `json:"evidence"`
	Recommendation string    `json:"recommendation"`
	CreatedAt      time.Time `json:"created_at"`
}

type GraphNode struct {
	ID       string         `json:"id"`
	ScanID   string         `json:"scan_id"`
	Kind     string         `json:"kind"`
	RefID    string         `json:"ref_id"`
	Label    string         `json:"label"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

type GraphEdge struct {
	ID     string `json:"id"`
	ScanID string `json:"scan_id"`
	FromID string `json:"from_id"`
	ToID   string `json:"to_id"`
	Type   string `json:"type"`
}

type AttackChainStep struct {
	Step        int    `json:"step"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Confidence  string `json:"confidence"`
}

type AttackChain struct {
	ID      string            `json:"id"`
	ScanID  string            `json:"scan_id"`
	Target  string            `json:"target"`
	Steps   []AttackChainStep `json:"steps"`
	Summary string            `json:"summary"`
}

type ScanStepResult struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"` // completed, failed
	Summary    string         `json:"summary,omitempty"`
	Severity   string         `json:"severity,omitempty"`
	Evidence   string         `json:"evidence,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
	StartedAt  time.Time      `json:"started_at,omitempty"`
	FinishedAt time.Time      `json:"finished_at,omitempty"`
	Category   string         `json:"category,omitempty"` // web, api, infra, recon
}

type ScanBundle struct {
	Scan            Scan            `json:"scan"`
	Target          Target          `json:"target"`
	Assets          []Asset         `json:"assets"`
	Services        []Service       `json:"services"`
	Applications    []Application   `json:"applications"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	GraphNodes      []GraphNode     `json:"graph_nodes"`
	GraphEdges      []GraphEdge     `json:"graph_edges"`
	AttackChain     AttackChain     `json:"attack_chain"`
	StepResults     []ScanStepResult`json:"step_results,omitempty"`
}
