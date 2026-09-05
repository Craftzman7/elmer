//go:build windows

package monitors

import (
	"encoding/xml"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

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
	evtRenderEventXml          = 1
	evtNextArraySize           = 64
)

func evtNoEvents(err syscall.Errno, returned uint32) bool {
	switch err {
	case windows.ERROR_NO_MORE_ITEMS, windows.WAIT_TIMEOUT, windows.ERROR_TIMEOUT:
		return true
	case windows.ERROR_INVALID_OPERATION:
		// Win11 empty pull: not ERROR_NO_MORE_ITEMS (winlogbeat same munge).
		return returned == 0
	}
	return false
}

// evtSubscription is a pull-mode subscription to one channel/query.
type evtSubscription struct {
	handle syscall.Handle
	signal windows.Handle
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
	// Manual-reset event kept for the life of the subscription. Closing it
	// after EvtSubscribe (a winlogbeat shortcut) makes Win11 EvtNext return
	// ERROR_INVALID_OPERATION on every empty poll, which we used to treat as
	// fatal and tear the monitor down.
	sig, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil || sig == 0 {
		return nil, fmt.Errorf("EvtSubscribe(%s): CreateEvent: %w", channel, err)
	}
	// SyscallN (not LazyProc.Call): ARM64 Call() with 8 args mis-marshals
	// the last parameters and Win11 returns ERROR_INVALID_PARAMETER.
	h, _, callErr := syscall.SyscallN(procEvtSubscribe.Addr(),
		0,
		uintptr(sig),
		uintptr(unsafe.Pointer(pch)),
		uintptr(unsafe.Pointer(pq)),
		0, 0, 0,
		uintptr(evtSubscribeToFutureEvents),
	)
	if h == 0 {
		windows.CloseHandle(sig)
		return nil, fmt.Errorf("EvtSubscribe(%s): %w", channel, syscall.Errno(callErr))
	}
	return &evtSubscription{handle: syscall.Handle(h), signal: sig}, nil
}

func (s *evtSubscription) close() {
	if s.handle != 0 {
		procEvtClose.Call(uintptr(s.handle))
		s.handle = 0
	}
	if s.signal != 0 {
		windows.CloseHandle(s.signal)
		s.signal = 0
	}
}

// next waits up to timeoutMs for the subscription signal, then drains
// available events. An empty result is not an error.
func (s *evtSubscription) next(timeoutMs uint32) ([]string, error) {
	if s.signal != 0 {
		_, _ = windows.WaitForSingleObject(s.signal, timeoutMs)
	}
	var out []string
	for {
		batch, err := s.pull()
		if err != nil {
			return out, err
		}
		if len(batch) == 0 {
			if s.signal != 0 {
				_ = windows.ResetEvent(s.signal)
			}
			return out, nil
		}
		out = append(out, batch...)
	}
}

func (s *evtSubscription) pull() ([]string, error) {
	var evts [evtNextArraySize]syscall.Handle
	var returned uint32
	ok, _, errno := syscall.SyscallN(procEvtNext.Addr(),
		uintptr(s.handle),
		uintptr(evtNextArraySize),
		uintptr(unsafe.Pointer(&evts[0])),
		0, // timeout: the signal event already gated us
		0,
		uintptr(unsafe.Pointer(&returned)),
	)
	if ok == 0 {
		code := syscall.Errno(errno)
		if evtNoEvents(code, returned) {
			return nil, nil
		}
		return nil, code
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
	var bufSize, propCount uint32
	procEvtRender.Call(0, uintptr(h), evtRenderEventXml, 0, 0,
		uintptr(unsafe.Pointer(&bufSize)), uintptr(unsafe.Pointer(&propCount)))
	if bufSize == 0 {
		return "", fmt.Errorf("EvtRender: no size")
	}
	buf := make([]uint16, bufSize/2)
	var used uint32
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
		EventID     int    `xml:"EventID"`
		Computer    string `xml:"Computer"`
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
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
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
