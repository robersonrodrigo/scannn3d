package recon

import "time"

type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
)

type ReconInput struct {
	Target  string       `json:"target"`
	ASN     string       `json:"asn,omitempty"`
	Modules []string     `json:"modules,omitempty"`
	Options ReconOptions `json:"options,omitempty"`
}

type ReconOptions struct {
	Ports        string `json:"ports,omitempty"`
	CustomPorts  string `json:"custom_ports,omitempty"`
	UseCloudlist bool   `json:"use_cloudlist,omitempty"`
	UseChaos     bool   `json:"use_chaos,omitempty"`
	UseUncover   bool   `json:"use_uncover,omitempty"`
	Force        bool   `json:"force,omitempty"`
}

type Domain struct {
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

type Subdomain struct {
	Value  string `json:"value"`
	Source string `json:"source,omitempty"`
}

type IPAsset struct {
	Value  string `json:"value"`
	Host   string `json:"host,omitempty"`
	Source string `json:"source,omitempty"`
}

type PortAsset struct {
	Host     string `json:"host"`
	IP       string `json:"ip,omitempty"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Source   string `json:"source,omitempty"`
}

type URLAsset struct {
	Value  string `json:"value"`
	Host   string `json:"host,omitempty"`
	Source string `json:"source,omitempty"`
}

type ModuleRun struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	DurationMS int64          `json:"duration_ms"`
	CacheHit   bool           `json:"cache_hit"`
	Error      string         `json:"error,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
}

type Result struct {
	JobID      string         `json:"job_id"`
	Target     string         `json:"target"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt time.Time      `json:"finished_at"`
	Modules    []ModuleRun    `json:"modules"`
	Domains    []Domain       `json:"domains"`
	Subdomains []Subdomain    `json:"subdomains"`
	IPs        []IPAsset      `json:"ips"`
	Ports      []PortAsset    `json:"ports"`
	URLs       []URLAsset     `json:"urls"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

type Job struct {
	ID        string     `json:"id"`
	CreatedBy string     `json:"created_by"`
	Status    JobStatus  `json:"status"`
	Input     ReconInput `json:"input"`
	StartedAt time.Time  `json:"started_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	Error     string     `json:"error,omitempty"`
}

type Event struct {
	Seq      int64          `json:"seq"`
	Time     time.Time      `json:"time"`
	JobID    string         `json:"job_id"`
	Level    string         `json:"level"`
	Phase    string         `json:"phase"`
	Kind     string         `json:"kind"`
	Message  string         `json:"message"`
	Progress int            `json:"progress"`
	Data     map[string]any `json:"data,omitempty"`
}
