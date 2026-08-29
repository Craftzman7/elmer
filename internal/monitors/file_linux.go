//go:build linux

package monitors

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"elmer/internal/config"
	"elmer/internal/events"
	"elmer/internal/util"
)

// FileMonitor watches critical paths with inotify. Single files are watched
// via their parent directory (so atomic-rename replacements are caught);
// paths ending in "/" are watched recursively (new subdirs gain watches).
// elmer's own redirected stdout/stderr files are excluded to avoid
// self-monitoring feedback loops.
type FileMonitor struct {
	cfg  *config.Config
	caps []string

	mu      sync.Mutex
	watches map[int32]string           // wd → dir
	targets map[string]map[string]bool // dir → basenames of interest (empty set = all)
	exclude map[string]bool            // paths never reported
}

func NewFileMonitor(cfg *config.Config) *FileMonitor {
	excl := map[string]bool{}
	for _, p := range cfg.FIM.ExcludePaths {
		if abs, err := filepath.Abs(p); err == nil {
			excl[abs] = true
		}
	}
	// Own output sinks: prevents watching our own log file.
	for _, fd := range []string{"/proc/self/fd/1", "/proc/self/fd/2"} {
		if link, err := os.Readlink(fd); err == nil && strings.HasPrefix(link, "/") {
			excl[link] = true
		}
	}
	return &FileMonitor{cfg: cfg, exclude: excl}
}

func (m *FileMonitor) Name() string { return "fim" }

func (m *FileMonitor) Capabilities() []string { return m.caps }

const watchMask = unix.IN_MODIFY | unix.IN_CREATE | unix.IN_MOVED_TO |
	unix.IN_MOVED_FROM | unix.IN_DELETE | unix.IN_ATTRIB | unix.IN_DELETE_SELF |
	unix.IN_MOVE_SELF | unix.IN_ONLYDIR

func (m *FileMonitor) Start(ctx context.Context, out chan<- events.Event) error {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	m.watches = map[int32]string{}
	m.targets = map[string]map[string]bool{}

	added := 0
	for _, pat := range m.cfg.FIM.Paths {
		added += m.addWatchPattern(fd, pat)
	}
	if added == 0 {
		out <- DegradedNote("fim: no watchable paths found (check config fim.paths)")
		<-ctx.Done()
		return nil
	}
	m.caps = append(m.caps, fmt.Sprintf("inotify: %d directories watched", added))
	go func() { <-ctx.Done(); unix.Close(fd) }()

	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("inotify read: %w", err)
		}
		m.consume(buf[:n], fd, out)
	}
}

// addWatchPattern expands one config path into inotify watches.
func (m *FileMonitor) addWatchPattern(fd int, pat string) int {
	recursive := strings.HasSuffix(pat, "/")
	pat = strings.TrimSuffix(pat, "/")

	var candidates []string
	if strings.ContainsAny(pat, "*?[") {
		candidates, _ = filepath.Glob(pat)
	} else {
		// Literal path: keep it even if it doesn't exist yet — watching its
		// parent catches the creation (e.g. /etc/ld.so.preload appearing).
		candidates = []string{pat}
	}
	added := 0
	for _, p := range candidates {
		st, err := os.Stat(p)
		switch {
		case err != nil && recursive:
			continue
		case err != nil:
			// Nonexistent file: watch parent, filter to this basename.
			dir := filepath.Dir(p)
			if dst, derr := os.Stat(dir); derr == nil && dst.IsDir() {
				added += m.watchDir(fd, dir, []string{filepath.Base(p)})
			}
		case st.IsDir() && recursive:
			added += m.watchTree(fd, p)
		case st.IsDir():
			added += m.watchDir(fd, p, nil) // all entries in this dir
		default:
			// Single file: watch parent, filter to this basename so rename
			// replacements (editors, apt) are seen as IN_MOVED_TO.
			dir := filepath.Dir(p)
			added += m.watchDir(fd, dir, []string{filepath.Base(p)})
		}
	}
	return added
}

func (m *FileMonitor) watchTree(fd int, root string) int {
	added := 0
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable subdirs are skipped, not fatal
		}
		if d.IsDir() {
			added += m.watchDir(fd, p, nil)
		}
		return nil
	})
	return added
}

// watchDir adds an inotify watch on dir. names is nil to track every entry,
// or a basename filter list for single-file targets.
func (m *FileMonitor) watchDir(fd int, dir string, names []string) int {
	wd, err := unix.InotifyAddWatch(fd, dir, watchMask)
	if err != nil {
		return 0
	}
	m.mu.Lock()
	m.watches[int32(wd)] = dir
	set, ok := m.targets[dir]
	if !ok {
		set = map[string]bool{}
		m.targets[dir] = set
	}
	if names != nil {
		for _, n := range names {
			set[n] = true
		}
	}
	m.mu.Unlock()
	return 1
}

func (m *FileMonitor) consume(b []byte, fd int, out chan<- events.Event) {
	for off := 0; off+16 <= len(b); {
		wd := int32(binary.LittleEndian.Uint32(b[off:]))
		mask := binary.LittleEndian.Uint32(b[off+4:])
		// cookie(4) at off+8, len(4) at off+12
		nameLen := int(binary.LittleEndian.Uint32(b[off+12:]))
		name := ""
		if nameLen > 0 && off+16+nameLen <= len(b) {
			name = strings.TrimRight(string(b[off+16:off+16+nameLen]), "\x00")
		}
		off += 16 + nameLen

		m.mu.Lock()
		dir := m.watches[wd]
		filter, tracked := m.targets[dir]
		m.mu.Unlock()

		if mask&unix.IN_Q_OVERFLOW != 0 {
			out <- events.Event{
				Time:     time.Now(),
				Severity: events.High,
				Category: events.CatFile,
				Title:    "inotify queue overflow",
				Message:  "events were lost; elmer may have missed file changes",
				Host:     events.Host,
			}
			continue
		}
		if dir == "" || name == "" {
			continue
		}
		// Apply the single-file filter.
		if tracked && len(filter) > 0 && !filter[name] {
			continue
		}

		path := filepath.Join(dir, name)
		if m.exclude[path] {
			continue
		}
		isDir := mask&unix.IN_ISDIR != 0

		// New subdir inside a recursive watch gains its own watch.
		if isDir && mask&(unix.IN_CREATE|unix.IN_MOVED_TO) != 0 {
			m.watchTree(fd, path)
		}

		if ev, ok := fileEvent(mask, path); ok {
			out <- ev
		}
	}
}

func fileEvent(mask uint32, path string) (events.Event, bool) {
	var op, title string
	sev := events.Info
	switch {
	case mask&unix.IN_CREATE != 0 || mask&unix.IN_MOVED_TO != 0:
		op, title = "create", "file created"
		sev = events.Low
	case mask&unix.IN_MOVED_FROM != 0 || mask&unix.IN_DELETE != 0:
		op, title = "delete", "file deleted"
		sev = events.Low
	case mask&unix.IN_ATTRIB != 0:
		op, title = "attrib", "file attributes changed"
	case mask&unix.IN_MODIFY != 0:
		op, title = "modify", "file modified"
	default:
		return events.Event{}, false
	}
	ev := events.Event{
		Time:     time.Now(),
		Severity: sev,
		Category: events.CatFile,
		Title:    title,
		Host:     events.Host,
	}
	ev.With("path", path)
	ev.With("op", op)
	ev.With("size", strconv.FormatInt(fileSize(path), 10))
	ev.With("sha256", hashFor(path))
	return ev, true
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return -1
	}
	return st.Size()
}

func hashFor(path string) string {
	if st, err := os.Stat(path); err == nil && !st.IsDir() && st.Size() <= 4<<20 {
		return util.HashFile(path)
	}
	return ""
}
