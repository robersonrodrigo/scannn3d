package config

import "time"

type AuthType string

const (
	AuthNone   AuthType = "none"
	AuthBearer AuthType = "bearer"
	AuthBasic  AuthType = "basic"
	AuthAPIKey AuthType = "apikey"
)

type AuthConfig struct {
	Type      AuthType
	Token     string
	Username  string
	Password  string
	APIKey    string
	APIHeader string
}

type Config struct {
	Target             string
	Endpoints          []string
	OpenAPIFile        string
	PostmanFile        string
	Crawl              bool
	CrawlDepth         int
	ExternalTools      []string
	ExternalTimeout    time.Duration
	DirsearchProfile   string
	DirsearchIntensity string
	DirsearchEnabled   bool
	Method             string
	Body               string
	Headers            map[string]string
	Rate               int
	Burst              int
	Concurrency        int
	Timeout            time.Duration
	InsecureTLS        bool
	ScopeHosts         []string
	Modules            []string
	TemplateDir        string
	OutputDir          string
	Format             string
	Verbose            bool
	Auth               AuthConfig
}
