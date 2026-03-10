package recon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Service struct {
	logger *slog.Logger
	cache  *Cache

	mu      sync.RWMutex
	jobs    map[string]Job
	results map[string]Result
	events  map[string][]Event
	subs    map[string]map[chan Event]struct{}
	workers chan struct{}
	seq     atomic.Int64
	idSeq   atomic.Uint64
}

func NewService(logger *slog.Logger, cache *Cache, maxConcurrent int) *Service {
	if maxConcurrent <= 0 {
		maxConcurrent = 2
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		logger:  logger,
		cache:   cache,
		jobs:    map[string]Job{},
		results: map[string]Result{},
		events:  map[string][]Event{},
		subs:    map[string]map[chan Event]struct{}{},
		workers: make(chan struct{}, maxConcurrent),
	}
}

func (s *Service) CreateJob(input ReconInput, createdBy string) (Job, error) {
	input.Target = strings.TrimSpace(input.Target)
	if input.Target == "" {
		return Job{}, fmt.Errorf("target required")
	}
	if strings.TrimSpace(input.ASN) == "" && !strings.Contains(input.Target, ".") && net.ParseIP(input.Target) == nil {
		return Job{}, fmt.Errorf("target must be valid domain/ip or provide asn")
	}
	if len(input.Modules) == 0 {
		input.Modules = []string{"pipeline"}
	}
	id := fmt.Sprintf("recon-%d", s.idSeq.Add(1))
	now := time.Now().UTC()
	job := Job{
		ID:        id,
		CreatedBy: createdBy,
		Status:    JobQueued,
		Input:     input,
		StartedAt: now,
		UpdatedAt: now,
	}
	s.mu.Lock()
	s.jobs[id] = job
	s.mu.Unlock()
	s.emit(id, "INFO", "queued", "job_queued", "Recon job enfileirado.", 1, map[string]any{"target": input.Target})
	go s.runJob(job)
	return job, nil
}

func (s *Service) ListJobs() []Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		out = append(out, j)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	return out
}

func (s *Service) GetJob(id string) (Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	return j, ok
}

func (s *Service) GetResult(id string) (Result, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.results[id]
	return r, ok
}

func (s *Service) History(jobID string, since int64) []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.events[jobID]
	if since <= 0 {
		out := make([]Event, len(all))
		copy(out, all)
		return out
	}
	out := make([]Event, 0, len(all))
	for _, ev := range all {
		if ev.Seq > since {
			out = append(out, ev)
		}
	}
	return out
}

func (s *Service) LastSeq(jobID string) int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	all := s.events[jobID]
	if len(all) == 0 {
		return 0
	}
	return all[len(all)-1].Seq
}

func (s *Service) Subscribe(jobID string) (<-chan Event, func()) {
	ch := make(chan Event, 32)
	s.mu.Lock()
	if s.subs[jobID] == nil {
		s.subs[jobID] = map[chan Event]struct{}{}
	}
	s.subs[jobID][ch] = struct{}{}
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		if m := s.subs[jobID]; m != nil {
			delete(m, ch)
		}
		s.mu.Unlock()
		close(ch)
	}
	return ch, cancel
}

func (s *Service) Rerun(jobID, userID string) (Job, error) {
	j, ok := s.GetJob(jobID)
	if !ok {
		return Job{}, errors.New("job not found")
	}
	input := j.Input
	input.Options.Force = true
	return s.CreateJob(input, userID)
}

func (s *Service) runJob(job Job) {
	s.workers <- struct{}{}
	defer func() { <-s.workers }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	s.updateStatus(job.ID, JobRunning, "")
	s.emit(job.ID, "INFO", "start", "job_started", "Recon job iniciado.", 3, map[string]any{"target": job.Input.Target})

	state := newState(job)
	modules := s.resolveModules(job.Input)
	for i, mod := range modules {
		progress := 5 + int(float64(i)/float64(max(1, len(modules)))*85)
		s.emit(job.ID, "INFO", mod.Name(), "module_started", "Modulo iniciado.", progress, map[string]any{"module": mod.Name()})
		mr := s.runModuleWithCache(ctx, job, mod, state)
		state.result.Modules = append(state.result.Modules, mr)
		if mr.Error != "" {
			s.emit(job.ID, "WARN", mod.Name(), "module_error", "Modulo finalizado com erro.", progress+4, map[string]any{"module": mod.Name(), "error": mr.Error})
		} else {
			s.emit(job.ID, "INFO", mod.Name(), "module_completed", "Modulo concluido.", progress+4, map[string]any{"module": mod.Name(), "cache_hit": mr.CacheHit})
		}
	}
	state.finalize()
	s.mu.Lock()
	s.results[job.ID] = state.result
	s.mu.Unlock()
	s.updateStatus(job.ID, JobCompleted, "")
	s.emit(job.ID, "INFO", "completed", "job_completed", "Recon job finalizado.", 100, map[string]any{
		"domains":    len(state.result.Domains),
		"subdomains": len(state.result.Subdomains),
		"ips":        len(state.result.IPs),
		"ports":      len(state.result.Ports),
		"urls":       len(state.result.URLs),
	})
}

func (s *Service) runModuleWithCache(ctx context.Context, job Job, mod Module, state *pipelineState) ModuleRun {
	start := time.Now()
	inputKey := map[string]any{
		"target":  job.Input.Target,
		"asn":     job.Input.ASN,
		"options": job.Input.Options,
		"domains": state.domainValues(),
		"subs":    state.subdomainValues(),
		"ips":     state.ipValues(),
		"urls":    state.urlValues(),
	}
	k := hashJSON(inputKey)
	if !job.Input.Options.Force {
		if b, ok, err := s.cache.Get(ctx, mod.Name(), k); err == nil && ok {
			var cached moduleOutput
			if json.Unmarshal(b, &cached) == nil {
				state.apply(cached)
				return ModuleRun{Name: mod.Name(), Status: "completed", DurationMS: time.Since(start).Milliseconds(), CacheHit: true, Meta: map[string]any{"cached": true}}
			}
		}
	}
	out, err := mod.Run(ctx, ModuleRequest{Input: job.Input, State: state.snapshot()})
	mr := ModuleRun{Name: mod.Name(), DurationMS: time.Since(start).Milliseconds(), Status: "completed"}
	if err != nil {
		mr.Status = "failed"
		mr.Error = err.Error()
	}
	if out.Meta != nil {
		mr.Meta = out.Meta
	}
	state.apply(out)
	if b, err := json.Marshal(out); err == nil {
		_ = s.cache.Set(ctx, mod.Name(), k, b, ttlFor(mod.Name()))
	}
	return mr
}

func (s *Service) updateStatus(jobID string, status JobStatus, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[jobID]
	if !ok {
		return
	}
	j.Status = status
	j.Error = errMsg
	j.UpdatedAt = time.Now().UTC()
	s.jobs[jobID] = j
}

func (s *Service) emit(jobID, level, phase, kind, message string, progress int, data map[string]any) {
	ev := Event{
		Seq:      s.seq.Add(1),
		Time:     time.Now().UTC(),
		JobID:    jobID,
		Level:    level,
		Phase:    phase,
		Kind:     kind,
		Message:  message,
		Progress: progress,
		Data:     data,
	}
	s.mu.Lock()
	s.events[jobID] = append(s.events[jobID], ev)
	for ch := range s.subs[jobID] {
		select {
		case ch <- ev:
		default:
		}
	}
	s.mu.Unlock()
}

type ModuleRequest struct {
	Input ReconInput
	State Snapshot
}

type Module interface {
	Name() string
	Run(ctx context.Context, req ModuleRequest) (moduleOutput, error)
}

type Snapshot struct {
	Domains    []string
	Subdomains []string
	IPs        []string
	Ports      []PortAsset
	URLs       []string
}

type moduleOutput struct {
	Domains    []string       `json:"domains,omitempty"`
	Subdomains []string       `json:"subdomains,omitempty"`
	IPs        []IPAsset      `json:"ips,omitempty"`
	Ports      []PortAsset    `json:"ports,omitempty"`
	URLs       []string       `json:"urls,omitempty"`
	Meta       map[string]any `json:"meta,omitempty"`
}

type pipelineState struct {
	result     Result
	domains    map[string]Domain
	subdomains map[string]Subdomain
	ips        map[string]IPAsset
	ports      map[string]PortAsset
	urls       map[string]URLAsset
}

func newState(job Job) *pipelineState {
	now := time.Now().UTC()
	r := Result{JobID: job.ID, Target: job.Input.Target, StartedAt: now, Metadata: map[string]any{"pipeline": "recon"}}
	st := &pipelineState{
		result:     r,
		domains:    map[string]Domain{},
		subdomains: map[string]Subdomain{},
		ips:        map[string]IPAsset{},
		ports:      map[string]PortAsset{},
		urls:       map[string]URLAsset{},
	}
	if strings.Contains(job.Input.Target, ".") {
		st.domains[strings.ToLower(job.Input.Target)] = Domain{Value: strings.ToLower(job.Input.Target), Source: "input"}
	}
	if ip := net.ParseIP(job.Input.Target); ip != nil {
		st.ips[ip.String()] = IPAsset{Value: ip.String(), Source: "input"}
	}
	return st
}

func (s *pipelineState) snapshot() Snapshot {
	return Snapshot{Domains: s.domainValues(), Subdomains: s.subdomainValues(), IPs: s.ipValues(), Ports: s.portValues(), URLs: s.urlValues()}
}

func (s *pipelineState) domainValues() []string {
	out := make([]string, 0, len(s.domains))
	for k := range s.domains {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func (s *pipelineState) subdomainValues() []string {
	out := make([]string, 0, len(s.subdomains))
	for k := range s.subdomains {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
func (s *pipelineState) ipValues() []string {
	out := make([]string, 0, len(s.ips))
	for k := range s.ips {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *pipelineState) portValues() []PortAsset {
	out := make([]PortAsset, 0, len(s.ports))
	for _, v := range s.ports {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Host == out[j].Host {
			return out[i].Port < out[j].Port
		}
		return out[i].Host < out[j].Host
	})
	return out
}
func (s *pipelineState) urlValues() []string {
	out := make([]string, 0, len(s.urls))
	for k := range s.urls {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *pipelineState) apply(out moduleOutput) {
	for _, d := range out.Domains {
		d := strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		s.domains[d] = Domain{Value: d, Source: "pipeline"}
	}
	for _, sub := range out.Subdomains {
		sub = strings.ToLower(strings.TrimSpace(sub))
		if sub == "" {
			continue
		}
		s.subdomains[sub] = Subdomain{Value: sub, Source: "pipeline"}
	}
	for _, ip := range out.IPs {
		v := strings.TrimSpace(ip.Value)
		if net.ParseIP(v) == nil {
			continue
		}
		ip.Value = v
		s.ips[v] = ip
	}
	for _, p := range out.Ports {
		if p.Port <= 0 {
			continue
		}
		k := fmt.Sprintf("%s:%d/%s", strings.ToLower(strings.TrimSpace(firstNonEmpty(p.Host, p.IP))), p.Port, firstNonEmpty(p.Protocol, "tcp"))
		p.Protocol = firstNonEmpty(p.Protocol, "tcp")
		s.ports[k] = p
	}
	for _, raw := range out.URLs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u := normalizeURL(raw)
		if u == "" {
			continue
		}
		s.urls[u] = URLAsset{Value: u, Host: hostFromAnyURL(u), Source: "pipeline"}
	}
}

func (s *pipelineState) finalize() {
	s.result.FinishedAt = time.Now().UTC()
	s.result.Domains = make([]Domain, 0, len(s.domains))
	for _, v := range s.domains {
		s.result.Domains = append(s.result.Domains, v)
	}
	s.result.Subdomains = make([]Subdomain, 0, len(s.subdomains))
	for _, v := range s.subdomains {
		s.result.Subdomains = append(s.result.Subdomains, v)
	}
	s.result.IPs = make([]IPAsset, 0, len(s.ips))
	for _, v := range s.ips {
		s.result.IPs = append(s.result.IPs, v)
	}
	s.result.Ports = make([]PortAsset, 0, len(s.ports))
	for _, v := range s.ports {
		s.result.Ports = append(s.result.Ports, v)
	}
	s.result.URLs = make([]URLAsset, 0, len(s.urls))
	for _, v := range s.urls {
		s.result.URLs = append(s.result.URLs, v)
	}
	sort.Slice(s.result.Domains, func(i, j int) bool { return s.result.Domains[i].Value < s.result.Domains[j].Value })
	sort.Slice(s.result.Subdomains, func(i, j int) bool { return s.result.Subdomains[i].Value < s.result.Subdomains[j].Value })
	sort.Slice(s.result.IPs, func(i, j int) bool { return s.result.IPs[i].Value < s.result.IPs[j].Value })
	sort.Slice(s.result.Ports, func(i, j int) bool {
		if s.result.Ports[i].Host == s.result.Ports[j].Host {
			return s.result.Ports[i].Port < s.result.Ports[j].Port
		}
		return s.result.Ports[i].Host < s.result.Ports[j].Host
	})
	sort.Slice(s.result.URLs, func(i, j int) bool { return s.result.URLs[i].Value < s.result.URLs[j].Value })
}

func (s *Service) resolveModules(input ReconInput) []Module {
	if len(input.Modules) == 1 && strings.EqualFold(input.Modules[0], "pipeline") {
		mods := make([]Module, 0, 10)
		if strings.TrimSpace(input.ASN) != "" {
			mods = append(mods, asnmapModule{})
		}
		mods = append(mods, subfinderModule{}, alterxModule{}, dnsModule{}, naabuModule{}, httpProbeModule{}, katanaModule{})
		if input.Options.UseChaos {
			mods = append(mods, chaosModule{})
		}
		if input.Options.UseUncover {
			mods = append(mods, uncoverModule{})
		}
		if input.Options.UseCloudlist {
			mods = append(mods, cloudlistModule{})
		}
		return mods
	}
	mods := make([]Module, 0, len(input.Modules))
	for _, name := range input.Modules {
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "asnmap":
			mods = append(mods, asnmapModule{})
		case "subfinder":
			mods = append(mods, subfinderModule{})
		case "alterx":
			mods = append(mods, alterxModule{})
		case "dns", "dnsx", "dns_resolution":
			mods = append(mods, dnsModule{})
		case "naabu":
			mods = append(mods, naabuModule{})
		case "http_probe", "httpx", "probe":
			mods = append(mods, httpProbeModule{})
		case "katana":
			mods = append(mods, katanaModule{})
		case "chaos":
			mods = append(mods, chaosModule{})
		case "uncover":
			mods = append(mods, uncoverModule{})
		case "cloudlist":
			mods = append(mods, cloudlistModule{})
		}
	}
	if len(mods) == 0 {
		return []Module{subfinderModule{}, alterxModule{}, dnsModule{}, naabuModule{}, httpProbeModule{}, katanaModule{}}
	}
	return mods
}

func runTool(ctx context.Context, name string, args ...string) ([]byte, error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s not installed", name)
	}
	tctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(tctx, bin, args...)
	b, err := cmd.CombinedOutput()
	if tctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("%s timed out", name)
	}
	if err != nil {
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s failed: %s", name, msg)
	}
	return b, nil
}

func ttlFor(module string) time.Duration {
	switch module {
	case "subfinder", "chaos", "uncover", "katana", "naabu":
		return 8 * time.Hour
	case "asnmap", "cloudlist":
		return 24 * time.Hour
	default:
		return 6 * time.Hour
	}
}

func hashJSON(v any) string {
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

func hostFromAnyURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

type asnmapModule struct{}

func (asnmapModule) Name() string { return "asnmap" }

type subfinderModule struct{}

func (subfinderModule) Name() string { return "subfinder" }

type alterxModule struct{}

func (alterxModule) Name() string { return "alterx" }

type dnsModule struct{}

func (dnsModule) Name() string { return "dns_resolution" }

type naabuModule struct{}

func (naabuModule) Name() string { return "naabu" }

type httpProbeModule struct{}

func (httpProbeModule) Name() string { return "http_probe" }

type katanaModule struct{}

func (katanaModule) Name() string { return "katana" }

type chaosModule struct{}

func (chaosModule) Name() string { return "chaos" }

type uncoverModule struct{}

func (uncoverModule) Name() string { return "uncover" }

type cloudlistModule struct{}

func (cloudlistModule) Name() string { return "cloudlist" }

func (asnmapModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	asn := strings.TrimSpace(req.Input.ASN)
	if asn == "" {
		return moduleOutput{}, nil
	}
	out, err := runTool(ctx, "asnmap", "-a", asn, "-silent")
	if err != nil {
		return moduleOutput{}, err
	}
	lines := splitLines(out)
	return moduleOutput{Meta: map[string]any{"cidrs": len(lines), "asn": asn}}, nil
}

func (subfinderModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	domain := strings.ToLower(strings.TrimSpace(req.Input.Target))
	if strings.Contains(domain, "://") {
		u, err := url.Parse(domain)
		if err == nil {
			domain = u.Hostname()
		}
	}
	if domain == "" || strings.Count(domain, ".") == 0 {
		if len(req.State.Domains) > 0 {
			domain = req.State.Domains[0]
		}
	}
	if domain == "" {
		return moduleOutput{}, fmt.Errorf("domain input required for subfinder")
	}
	out, err := runTool(ctx, "subfinder", "-d", domain, "-silent", "-all", "-oJ")
	if err != nil {
		return moduleOutput{}, err
	}
	subs := parseJSONLineHosts(out, []string{"host", "input"}, domain)
	if len(subs) == 0 {
		subs = filterDomainLines(splitLines(out), domain)
	}
	return moduleOutput{Domains: []string{domain}, Subdomains: subs, Meta: map[string]any{"count": len(subs)}}, nil
}

func (alterxModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	seed := uniqueStrings(append([]string{}, req.State.Subdomains...))
	if len(seed) == 0 && len(req.State.Domains) > 0 {
		d := req.State.Domains[0]
		seed = []string{"dev." + d, "staging." + d, "api." + d, "admin." + d}
	}
	if len(seed) == 0 {
		return moduleOutput{}, nil
	}
	if _, err := exec.LookPath("alterx"); err != nil {
		return moduleOutput{Subdomains: seed, Meta: map[string]any{"fallback": true, "reason": "alterx not installed"}}, nil
	}
	// Minimal MVP fallback behavior even when alterx exists to keep deterministic output.
	return moduleOutput{Subdomains: seed, Meta: map[string]any{"count": len(seed)}}, nil
}

func (dnsModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	hosts := uniqueStrings(append([]string{}, req.State.Subdomains...))
	if len(hosts) == 0 {
		hosts = req.State.Domains
	}
	if len(hosts) == 0 {
		return moduleOutput{}, nil
	}
	ips := make([]IPAsset, 0, len(hosts))
	for _, h := range hosts {
		resolved, err := net.DefaultResolver.LookupIPAddr(ctx, h)
		if err != nil {
			continue
		}
		for _, ip := range resolved {
			v := ip.IP.String()
			if net.ParseIP(v) == nil {
				continue
			}
			ips = append(ips, IPAsset{Value: v, Host: h, Source: "dns"})
		}
	}
	return moduleOutput{IPs: ips, Meta: map[string]any{"resolved": len(ips)}}, nil
}

func (naabuModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	hosts := req.State.Subdomains
	if len(hosts) == 0 {
		hosts = req.State.Domains
	}
	if len(hosts) == 0 {
		hosts = req.State.IPs
	}
	if len(hosts) == 0 {
		return moduleOutput{}, nil
	}
	args := []string{"-silent", "-json"}
	if strings.TrimSpace(req.Input.Options.CustomPorts) != "" {
		args = append(args, "-p", req.Input.Options.CustomPorts)
	} else if strings.TrimSpace(req.Input.Options.Ports) != "" {
		args = append(args, "-top-ports", strings.TrimPrefix(req.Input.Options.Ports, "top-"))
	} else {
		args = append(args, "-top-ports", "100")
	}
	for _, h := range hosts {
		args = append(args, "-host", h)
	}
	out, err := runTool(ctx, "naabu", args...)
	if err != nil {
		return moduleOutput{}, err
	}
	ports := parseNaabuJSON(out)
	return moduleOutput{Ports: ports, Meta: map[string]any{"open_ports": len(ports)}}, nil
}

func (httpProbeModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	c := &http.Client{Timeout: 5 * time.Second}
	urls := make([]string, 0, 64)
	seen := map[string]struct{}{}
	add := func(u string) {
		u = normalizeURL(u)
		if u == "" {
			return
		}
		if _, ok := seen[u]; ok {
			return
		}
		seen[u] = struct{}{}
		urls = append(urls, u)
	}
	for _, p := range req.State.URLs {
		add(p)
	}
	for _, p := range req.State.Ports {
		host := firstNonEmpty(p.Host, p.IP)
		if host == "" {
			continue
		}
		scheme := "http"
		if p.Port == 443 || p.Port == 8443 {
			scheme = "https"
		}
		add(fmt.Sprintf("%s://%s:%d", scheme, host, p.Port))
	}
	for _, h := range req.State.Subdomains {
		add("https://" + h)
		add("http://" + h)
	}
	alive := make([]string, 0, len(urls))
	for _, raw := range urls {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode > 0 {
			alive = append(alive, raw)
		}
	}
	return moduleOutput{URLs: alive, Meta: map[string]any{"alive": len(alive)}}, nil
}

func (katanaModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	if len(req.State.URLs) == 0 {
		return moduleOutput{}, nil
	}
	if _, err := exec.LookPath("katana"); err != nil {
		return moduleOutput{URLs: req.State.URLs, Meta: map[string]any{"fallback": true, "reason": "katana not installed"}}, nil
	}
	found := make([]string, 0, 128)
	for _, u := range req.State.URLs {
		out, err := runTool(ctx, "katana", "-u", u, "-silent", "-jsonl")
		if err != nil {
			continue
		}
		found = append(found, parseJSONLineURLs(out, []string{"url", "request.endpoint"})...)
	}
	if len(found) == 0 {
		found = req.State.URLs
	}
	return moduleOutput{URLs: uniqueStrings(found), Meta: map[string]any{"urls": len(found)}}, nil
}

func (chaosModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	if _, err := exec.LookPath("chaos"); err != nil {
		return moduleOutput{}, err
	}
	target := req.Input.Target
	out, err := runTool(ctx, "chaos", "-d", target, "-silent")
	if err != nil {
		return moduleOutput{}, err
	}
	subs := filterDomainLines(splitLines(out), target)
	return moduleOutput{Subdomains: subs, Meta: map[string]any{"count": len(subs)}}, nil
}

func (uncoverModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	if _, err := exec.LookPath("uncover"); err != nil {
		return moduleOutput{}, err
	}
	out, err := runTool(ctx, "uncover", "-q", req.Input.Target, "-silent", "-json")
	if err != nil {
		return moduleOutput{}, err
	}
	urls := parseJSONLineURLs(out, []string{"url", "host"})
	return moduleOutput{URLs: urls, Meta: map[string]any{"count": len(urls)}}, nil
}

func (cloudlistModule) Run(ctx context.Context, req ModuleRequest) (moduleOutput, error) {
	if _, err := exec.LookPath("cloudlist"); err != nil {
		return moduleOutput{}, err
	}
	out, err := runTool(ctx, "cloudlist", "-silent", "-json")
	if err != nil {
		return moduleOutput{}, err
	}
	hosts := parseJSONLineHosts(out, []string{"hostname", "name", "host"}, req.Input.Target)
	return moduleOutput{Subdomains: hosts, Meta: map[string]any{"count": len(hosts)}}, nil
}

func splitLines(b []byte) []string {
	out := make([]string, 0)
	for _, ln := range strings.Split(string(b), "\n") {
		v := strings.TrimSpace(ln)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func filterDomainLines(lines []string, domain string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if strings.Contains(domain, "://") {
		if u, err := url.Parse(domain); err == nil {
			domain = u.Hostname()
		}
	}
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		v := strings.ToLower(strings.TrimSpace(ln))
		if v == "" {
			continue
		}
		if strings.HasSuffix(v, "."+domain) || v == domain {
			out = append(out, v)
		}
	}
	return uniqueStrings(out)
}

func parseJSONLineHosts(b []byte, keys []string, scopeDomain string) []string {
	lines := splitLines(b)
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) != nil {
			continue
		}
		for _, k := range keys {
			if v := getNestedString(m, k); v != "" {
				out = append(out, strings.ToLower(v))
			}
		}
	}
	if scopeDomain != "" {
		return filterDomainLines(out, scopeDomain)
	}
	return uniqueStrings(out)
}

func parseJSONLineURLs(b []byte, keys []string) []string {
	lines := splitLines(b)
	out := make([]string, 0, len(lines))
	for _, ln := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) != nil {
			continue
		}
		for _, k := range keys {
			if v := getNestedString(m, k); v != "" {
				if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") {
					out = append(out, v)
				}
			}
		}
	}
	return uniqueStrings(out)
}

func parseNaabuJSON(b []byte) []PortAsset {
	lines := splitLines(b)
	out := make([]PortAsset, 0, len(lines))
	for _, ln := range lines {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) != nil {
			continue
		}
		host := getNestedString(m, "host")
		ip := getNestedString(m, "ip")
		port := intFromAny(m["port"])
		if port <= 0 {
			continue
		}
		out = append(out, PortAsset{Host: host, IP: ip, Port: port, Protocol: "tcp", Source: "naabu"})
	}
	return out
}

func getNestedString(m map[string]any, path string) string {
	parts := strings.Split(path, ".")
	var cur any = m
	for _, p := range parts {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	if s, ok := cur.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func intFromAny(v any) int {
	switch vv := v.(type) {
	case float64:
		return int(vv)
	case int:
		return vv
	case string:
		var i int
		_, _ = fmt.Sscanf(vv, "%d", &i)
		return i
	default:
		return 0
	}
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, it := range in {
		it = strings.TrimSpace(strings.ToLower(it))
		if it == "" {
			continue
		}
		if _, ok := seen[it]; ok {
			continue
		}
		seen[it] = struct{}{}
		out = append(out, it)
	}
	sort.Strings(out)
	return out
}
