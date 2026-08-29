//go:build windows

package monitors

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"elmer/internal/config"
	"elmer/internal/events"
)

// FileMonitor watches directories with ReadDirectoryChangesW (one goroutine
// per directory, recursive) and polls registry Run keys.
type FileMonitor struct {
	cfg  *config.Config
	caps []string
}

func NewFileMonitor(cfg *config.Config) *FileMonitor {
	return &FileMonitor{cfg: cfg}
}

func (m *FileMonitor) Name() string { return "fim" }

func (m *FileMonitor) Capabilities() []string { return m.caps }

const (
	fileListDirectory   = 0x0001
	fileFlagBackupSem   = 0x02000000
	notifyChangeName    = 0x00000001 | 0x00000002 | 0x00000004 // add/remove/rename
	notifyChangeAttrs   = 0x00000010                            // attributes
	notifyChangeLastWr  = 0x00000020                            // write
	notifyChangeSize    = 0x00000040
	notifyAll           = notifyChangeName | notifyChangeAttrs | notifyChangeLastWr | notifyChangeSize
)

func (m *FileMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	var wg sync.WaitGroup
	watched := 0
	for _, p := range m.cfg.FIM.Paths {
		expanded, err := filepath.Abs(strings.TrimSuffix(p, "\\"))
		if err != nil {
			continue
		}
		if fi, err := os.Stat(expanded); err != nil || !fi.IsDir() {
			continue
		}
		watched++
		wg.Add(1)
		go func(dir string) {
			defer wg.Done()
			m.watchDir(ctx, out, dir)
		}(expanded)
	}
	if watched == 0 {
		out <- DegradedNote("fim: no watchable directories found")
	}
	m.caps = append(m.caps, fmt.Sprintf("ReadDirectoryChangesW on %d paths, registry run keys", watched))

	// Registry run keys alongside the directory watchers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		m.watchRunKeys(ctx, out)
	}()

	wg.Wait()
	return nil
}

// watchDir runs a synchronous ReadDirectoryChangesW loop for one directory.
func (m *FileMonitor) watchDir(ctx context.Context, out chan<- events.Event, dir string) {
	pdir, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	h, err := windows.CreateFile(
		pdir,
		fileListDirectory,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		fileFlagBackupSem|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)

	overlapped := &windows.Overlapped{}
	evt, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil || evt == 0 {
		return // completion would be undetectable without an event
	}
	overlapped.HEvent = evt
	defer windows.CloseHandle(overlapped.HEvent)

	buf := make([]byte, 64*1024)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		var n uint32
		err := windows.ReadDirectoryChanges(
			h, &buf[0], uint32(len(buf)), true,
			notifyAll, &n, overlapped, 0,
		)
		if err != nil {
			return
		}
		// The read is pending; wait on its event, waking periodically to
		// honor ctx. Never re-issue while an operation is outstanding.
		signaled := false
		for !signaled {
			s, werr := windows.WaitForSingleObject(overlapped.HEvent, 1000)
			if werr != nil {
				return
			}
			if s == windows.WAIT_OBJECT_0 {
				signaled = true
			} else if ctx.Err() != nil {
				return
			}
		}
		if err := windows.GetOverlappedResult(h, overlapped, &n, false); err != nil {
			return
		}
		m.consume(buf[:n], dir, out)
	}
}

func (m *FileMonitor) consume(b []byte, dir string, out chan<- events.Event) {
	for off := 0; off+12 <= len(b); {
		next := binary.LittleEndian.Uint32(b[off:])
		action := binary.LittleEndian.Uint32(b[off+4:])
		nameLen := binary.LittleEndian.Uint32(b[off+8:])
		if off+12+int(nameLen) > len(b) {
			return
		}
		name := windows.UTF16ToString((*[4096]uint16)(unsafe.Pointer(&b[off+12]))[: nameLen/2])
		if next == 0 {
			off = len(b)
		} else {
			off += int(next)
		}
		if name == "" {
			continue
		}
		path := filepath.Join(dir, name)

		var title string
		sev := events.Info
		switch action {
		case 1: // FILE_ACTION_ADDED
			title, sev = "file created", events.Low
		case 2: // REMOVED
			title, sev = "file deleted", events.Low
		case 3: // MODIFIED
			title = "file modified"
		case 4, 5: // RENAMED old/new name
			title = "file renamed"
		default:
			continue
		}
		ev := events.Event{
			Time:     time.Now(),
			Severity: sev,
			Category: events.CatFile,
			Title:    title,
			Host:     events.Host,
		}
		ev.With("path", path)
		out <- ev
	}
}

// ---- registry Run keys -------------------------------------------------------

var runKeyPaths = []struct {
	root                             registry.Key
	path                             string
}{
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\Run`},
	{registry.LOCAL_MACHINE, `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{registry.LOCAL_MACHINE, `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
}

func (m *FileMonitor) watchRunKeys(ctx context.Context, out chan<- events.Event) {
	prev := readRunKeys()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur := readRunKeys()
			for k, v := range cur {
				if pv, ok := prev[k]; !ok {
					out <- runKeyEvent(events.High, "new Run key entry", k, v)
				} else if pv != v {
					out <- runKeyEvent(events.Medium, "Run key value changed", k, v)
				}
			}
			for k := range prev {
				if _, ok := cur[k]; !ok {
					out <- runKeyEvent(events.Medium, "Run key entry removed", k, "")
				}
			}
			prev = cur
		}
	}
}

func readRunKeys() map[string]string {
	out := map[string]string{}
	for _, rk := range runKeyPaths {
		k, err := registry.OpenKey(rk.root, rk.path, registry.READ)
		if err != nil {
			continue
		}
		names, _ := k.ReadValueNames(-1)
		for _, n := range names {
			v, _, err := k.GetStringValue(n)
			if err != nil {
				continue
			}
			out[rk.path+"\\"+n] = v
		}
		k.Close()
	}
	return out
}

func runKeyEvent(sev events.Severity, title, key, value string) events.Event {
	ev := events.Event{
		Time:     time.Now(),
		Severity: sev,
		Category: events.CatPersistence,
		Title:    title,
		Message:  key + " = " + value,
		Host:     events.Host,
		Technique: "T1547.001",
		Key:      "runkey/" + key,
	}
	return ev
}
