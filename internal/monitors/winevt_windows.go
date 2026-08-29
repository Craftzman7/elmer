//go:build windows

package monitors

import (
	"encoding/xml"
	"fmt"
	"syscall"
	"unsafe"

	"elmer/internal/events"
)

// winevt wraps the wevtapi.dll subscription API in pull mode.
var (
	modwevtapi       = syscall.NewLazyDLL("wevtapi.dll")
	procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
	procEvtNext      = modwevtapi.NewProc("EvtNext")
	procEvtRender    = modwevtapi.NewProc("EvtRender")
	procEvtClose     = modwevtapi.NewProc("EvtClose")
)

const (
	evtSubscribeToFutureEvents = 1
	evtSubscribePull           = 0x100
	evtRenderEventXml          = 1

	evtNextArraySize = 64
)

// evtSubscription is a pull-mode subscription to one channel/query.
type evtSubscription struct {
	handle syscall.Handle
}

func evtSubscribe(channel, query string) (*evtSubscription, error) {
	pch, err := syscall.UTF16PtrFromString(channel)
	if err != nil {
		return nil, err
	}
	pq, err := syscall.UTF16PtrFromString(query)
	if err != nil {
		return nil, err
	}
	h, _, err := procEvtSubscribe.Call(
		0,                 // session (local)
		0,                 // signal (pull mode)
		uintptr(unsafe.Pointer(pch)),
		uintptr(unsafe.Pointer(pq)),
		0, 0, 0,
		evtSubscribeToFutureEvents|evtSubscribePull,
	)
	if h == 0 {
		return nil, fmt.Errorf("EvtSubscribe(%s): %w", channel, err)
	}
	return &evtSubscription{handle: syscall.Handle(h)}, nil
}

func (s *evtSubscription) close() {
	if s.handle != 0 {
		procEvtClose.Call(uintptr(s.handle))
		s.handle = 0
	}
}

// next blocks up to timeoutMs and returns rendered event XML strings.
func (s *evtSubscription) next(timeoutMs uint32) ([]string, error) {
	var evts [evtNextArraySize]syscall.Handle
	var returned uint32
	ok, _, err := procEvtNext.Call(
		uintptr(s.handle),
		evtNextArraySize,
		uintptr(unsafe.Pointer(&evts[0])),
		uintptr(timeoutMs),
		uintptr(unsafe.Pointer(&returned)),
	)
	if ok == 0 {
		// ERROR_NO_MORE_ITEMS (259) or ERROR_TIMEOUT (253): no events now.
		if code := err.(syscall.Errno); code == 259 || code == 253 {
			return nil, nil
		}
		return nil, err
	}
	defer func() {
		for i := uint32(0); i < returned; i++ {
			procEvtClose.Call(uintptr(evts[i]))
		}
	}()

	var out []string
	for i := uint32(0); i < returned; i++ {
		xmlStr, err := renderEventXml(evts[i])
		if err != nil {
			continue
		}
		out = append(out, xmlStr)
	}
	return out, nil
}

func renderEventXml(h syscall.Handle) (string, error) {
	var bufSize uint32
	procEvtRender.Call(0, uintptr(h), evtRenderEventXml, 0, 0,
		uintptr(unsafe.Pointer(&bufSize)), 0)
	if bufSize == 0 {
		return "", fmt.Errorf("EvtRender: no size")
	}
	buf := make([]uint16, bufSize/2)
	var used, propCount uint32
	ok, _, err := procEvtRender.Call(0, uintptr(h), evtRenderEventXml,
		uintptr(bufSize), uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&propCount)))
	if ok == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf), nil
}

// ---- XML parsing -----------------------------------------------------------

type evtXml struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		EventID    int    `xml:"EventID"`
		Computer   string `xml:"Computer"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	EventData struct {
		Data []evtXmlData `xml:"Data"`
	} `xml:"EventData"`
}

type evtXmlData struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

// parseEvtXml decodes an event document into id, time, and named data.
func parseEvtXml(s string) (int, map[string]string, error) {
	var doc evtXml
	if err := xml.Unmarshal([]byte(s), &doc); err != nil {
		return 0, nil, err
	}
	data := map[string]string{}
	for _, d := range doc.EventData.Data {
		data[d.Name] = d.Value
	}
	return doc.System.EventID, data, nil
}

// evtField helpers build consistent events from winevt data.
func evtEvent(category, title string, sev events.Severity, data map[string]string) events.Event {
	ev := events.Event{
		Severity: sev,
		Category: category,
		Title:    title,
		Host:     events.Host,
	}
	for k, v := range data {
		ev.With(lowerASCII(k), v)
	}
	return ev
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 32
		}
	}
	return string(b)
}

// runEvtLoop drives a subscription until ctx is done, calling fn for each
// event XML document.
func runEvtLoop(stop <-chan struct{}, sub *evtSubscription, fn func(xml string)) error {
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		docs, err := sub.next(1000)
		if err != nil {
			return err
		}
		for _, d := range docs {
			fn(d)
		}
	}
}
