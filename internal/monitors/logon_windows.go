//go:build windows

package monitors

import (
	"context"
	"time"

	"elmer/internal/config"
	"elmer/internal/events"
)

const (
	LogonSuccess            = 4624
	LogonFail               = 4625
	Logoff                  = 4647
	UserCreated             = 4720
	UserEnabled             = 4722
	PasswordReset           = 4724
	AddedToGroupAD          = 4728
	AddedToGroupLocal       = 4732
	GroupChanged            = 4735
	ServiceInstalled        = 4697
	TaskCreated             = 4698
	TaskUpdated             = 4702
	SystemServiceInstalled  = 7045
	ServiceStartTypeChanged = 7040

	RDPLogon         = "10"
	NetworkLogon     = "3"
	InteractiveLogon = "2"
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
	case LogonSuccess:
		sev := events.Info
		switch data["LogonType"] {
		case RDPLogon:
			sev = events.Low
		case NetworkLogon: // network
			sev = events.Low
		case InteractiveLogon: // interactive
		}
		ev := evtEvent(events.CatAuth, "logon", sev, data)
		ev.Time = now
		ev.With("auth", "ok")
		if ip := data["IpAddress"]; ip != "" && ip != "-" && ip != "::1" && ip != "127.0.0.1" {
			ev.With("src_ip", ip)
		}
		return ev, true
	case LogonFail:
		ev := evtEvent(events.CatAuth, "logon failure", events.Medium, data)
		ev.Time = now
		ev.With("auth", "fail")
		if ip := data["IpAddress"]; ip != "" && ip != "-" {
			ev.With("src_ip", ip)
		}
		return ev, true
	case Logoff:
		ev := evtEvent(events.CatAuth, "logoff", events.Info, data)
		ev.Time = now
		return ev, true
	case UserCreated:
		ev := evtEvent(events.CatAuth, "user account created", events.Critical, data)
		ev.Time = now
		ev.Key = "winuser/" + data["TargetUserName"]
		return ev, true
	case UserEnabled:
		ev := evtEvent(events.CatAuth, "user account enabled", events.High, data)
		ev.Time = now
		return ev, true
	case PasswordReset:
		ev := evtEvent(events.CatAuth, "password reset", events.High, data)
		ev.Time = now
		return ev, true
	case AddedToGroupAD, AddedToGroupLocal:
		ev := evtEvent(events.CatAuth, "user added to group", events.High, data)
		ev.Time = now
		if data["TargetUserName"] == "Administrators" {
			ev.Severity = events.Critical
		}
		return ev, true
	case GroupChanged:
		ev := evtEvent(events.CatAuth, "group changed", events.Medium, data)
		ev.Time = now
		return ev, true
	case ServiceInstalled:
		ev := evtEvent(events.CatPersistence, "service installed", events.Critical, data)
		ev.Time = now
		ev.Technique = "T1543.003"
		return ev, true
	case TaskCreated:
		ev := evtEvent(events.CatPersistence, "scheduled task created", events.High, data)
		ev.Time = now
		ev.Technique = "T1053.005"
		return ev, true
	case TaskUpdated:
		ev := evtEvent(events.CatPersistence, "scheduled task updated", events.Medium, data)
		ev.Time = now
		return ev, true
	case SystemServiceInstalled:
		ev := evtEvent(events.CatPersistence, "service installed", events.Critical, data)
		ev.Time = now
		ev.Technique = "T1543.003"
		return ev, true
	case ServiceStartTypeChanged:
		ev := evtEvent(events.CatPersistence, "service start type changed", events.Medium, data)
		ev.Time = now
		return ev, true
	}
	return events.Event{}, false
}
