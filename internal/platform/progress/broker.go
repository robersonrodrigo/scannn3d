package progress

import (
	"sync"
	"time"
)

type ScanEvent struct {
	ScanID   string         `json:"scan_id"`
	Seq      int64          `json:"seq"`
	Time     time.Time      `json:"time"`
	Level    string         `json:"level"`
	Phase    string         `json:"phase"`
	Kind     string         `json:"kind"`
	Message  string         `json:"message"`
	Progress int            `json:"progress,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type Broker struct {
	mu        sync.RWMutex
	maxEvents int
	seq       map[string]int64
	events    map[string][]ScanEvent
	subs      map[string]map[int]chan ScanEvent
	nextSubID int
}

func NewBroker(maxEvents int) *Broker {
	if maxEvents <= 0 {
		maxEvents = 1000
	}
	return &Broker{
		maxEvents: maxEvents,
		seq:       map[string]int64{},
		events:    map[string][]ScanEvent{},
		subs:      map[string]map[int]chan ScanEvent{},
	}
}

func (b *Broker) Publish(ev ScanEvent) ScanEvent {
	b.mu.Lock()
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	if ev.Level == "" {
		ev.Level = "INFO"
	}
	if ev.Kind == "" {
		ev.Kind = "log"
	}
	b.seq[ev.ScanID]++
	ev.Seq = b.seq[ev.ScanID]
	buf := append(b.events[ev.ScanID], ev)
	if len(buf) > b.maxEvents {
		buf = buf[len(buf)-b.maxEvents:]
	}
	b.events[ev.ScanID] = buf

	targets := make([]chan ScanEvent, 0, len(b.subs[ev.ScanID]))
	for _, ch := range b.subs[ev.ScanID] {
		targets = append(targets, ch)
	}
	b.mu.Unlock()

	for _, ch := range targets {
		select {
		case ch <- ev:
		default:
		}
	}
	return ev
}

func (b *Broker) Subscribe(scanID string) (<-chan ScanEvent, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.nextSubID++
	id := b.nextSubID
	ch := make(chan ScanEvent, 128)
	if b.subs[scanID] == nil {
		b.subs[scanID] = map[int]chan ScanEvent{}
	}
	b.subs[scanID][id] = ch

	cancel := func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if set, ok := b.subs[scanID]; ok {
			if _, exists := set[id]; exists {
				delete(set, id)
			}
			if len(set) == 0 {
				delete(b.subs, scanID)
			}
		}
	}
	return ch, cancel
}

func (b *Broker) History(scanID string, since int64) []ScanEvent {
	b.mu.RLock()
	defer b.mu.RUnlock()
	src := b.events[scanID]
	if len(src) == 0 {
		return nil
	}
	out := make([]ScanEvent, 0, len(src))
	for _, ev := range src {
		if ev.Seq > since {
			out = append(out, ev)
		}
	}
	return out
}

func (b *Broker) LastSeq(scanID string) int64 {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.seq[scanID]
}
