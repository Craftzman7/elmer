//go:build windows

package monitors

import (
	"context"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
)

// AuthMonitor consumes logon, account, service, and scheduled-task events
// from the Security and System channels.
type AuthMonitor struct {
	cfg  *config.Config
	caps []string
}

func NewAuthMonitor(cfg *config.Config) *AuthMonitor {
	return &AuthMonitor{cfg: cfg}
}

func (m *AuthMonitor) Name() string { return "auth" }

func (m *AuthMonitor) Capabilities() []string { return m.caps }

const authQuery = "*[System[(EventID=4624 or EventID=4625 or EventID=4647 or " +
	"EventID=4720 or EventID=4722 or EventID=4724 or EventID=4728 or EventID=4732 or " +
	"EventID=4735 or EventID=4697 or EventID=4698 or EventID=4702)]]"

func (m *AuthMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	sec, err := evtSubscribe("Security", authQuery)
	if err != nil {
		out <- DegradedNote("auth: Security channel subscription failed: " + err.Error())
		<-ctx.Done()
		return nil
	}
	defer sec.close()
	m.caps = append(m.caps, "logon/account/service/task events (Security)")

	sys, err := evtSubscribe("System", "*[System[(EventID=7045 or EventID=7040)]]")
	if err == nil {
		defer sys.close()
		m.caps = append(m.caps, "service installs (System)")
		go runEvtLoop(ctx.Done(), sys, func(doc string) {
			if ev, ok := m.parse(time.Now(), doc); ok {
				out <- ev
			}
		})
	} else {
		out <- DegradedNote("auth: System channel subscription failed: " + err.Error())
	}

	return runEvtLoop(ctx.Done(), sec, func(doc string) {
		if ev, ok := m.parse(time.Now(), doc); ok {
			out <- ev
		}
	})
}

func (m *AuthMonitor) parse(now time.Time, doc string) (events.Event, bool) {
	id, data, err := parseEvtXml(doc)
	if err != nil {
		return events.Event{}, false
	}
	switch id {
	case 4624: // successful logon
		sev := events.Info
		switch data["LogonType"] {
		case "10": // RDP
			sev = events.Low
		case "3": // network
			sev = events.Low
		case "2": // interactive
		}
		ev := evtEvent(events.CatAuth, "logon", sev, data)
		ev.Time = now
		ev.With("auth", "ok")
		if ip := data["IpAddress"]; ip != "" && ip != "-" && ip != "::1" && ip != "127.0.0.1" {
			ev.With("src_ip", ip)
		}
		return ev, true
	case 4625: // failed logon
		ev := evtEvent(events.CatAuth, "logon failure", events.Medium, data)
		ev.Time = now
		ev.With("auth", "fail")
		if ip := data["IpAddress"]; ip != "" && ip != "-" {
			ev.With("src_ip", ip)
		}
		return ev, true
	case 4647: // logoff
		ev := evtEvent(events.CatAuth, "logoff", events.Info, data)
		ev.Time = now
		return ev, true
	case 4720: // user created
		ev := evtEvent(events.CatAuth, "user account created", events.Critical, data)
		ev.Time = now
		ev.Key = "winuser/" + data["TargetUserName"]
		return ev, true
	case 4722: // user enabled
		ev := evtEvent(events.CatAuth, "user account enabled", events.High, data)
		ev.Time = now
		return ev, true
	case 4724: // password reset
		ev := evtEvent(events.CatAuth, "password reset", events.High, data)
		ev.Time = now
		return ev, true
	case 4728, 4732: // added to group
		ev := evtEvent(events.CatAuth, "user added to group", events.High, data)
		ev.Time = now
		if data["TargetUserName"] == "Administrators" {
			ev.Severity = events.Critical
		}
		return ev, true
	case 4735: // group changed
		ev := evtEvent(events.CatAuth, "group changed", events.Medium, data)
		ev.Time = now
		return ev, true
	case 4697: // service installed
		ev := evtEvent(events.CatPersistence, "service installed", events.Critical, data)
		ev.Time = now
		ev.Technique = "T1543.003"
		return ev, true
	case 4698: // scheduled task created
		ev := evtEvent(events.CatPersistence, "scheduled task created", events.High, data)
		ev.Time = now
		ev.Technique = "T1053.005"
		return ev, true
	case 4702: // scheduled task updated
		ev := evtEvent(events.CatPersistence, "scheduled task updated", events.Medium, data)
		ev.Time = now
		return ev, true
	case 7045: // service installed (System)
		ev := evtEvent(events.CatPersistence, "service installed", events.Critical, data)
		ev.Time = now
		ev.Technique = "T1543.003"
		return ev, true
	case 7040: // service start type changed
		ev := evtEvent(events.CatPersistence, "service start type changed", events.Medium, data)
		ev.Time = now
		return ev, true
	}
	return events.Event{}, false
}
