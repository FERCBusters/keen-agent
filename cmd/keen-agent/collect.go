package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const maxRecord = 60000

// Pending groups are checkpointed in the same transaction as every consumed line.
// Interleaved auditd records share a durable group indexed by audit ID.
type Pending struct {
	Raw   string    `json:"raw"`
	Since time.Time `json:"since"`
	Last  time.Time `json:"last"`
}
type Checkpoint struct {
	Offset    int64              `json:"offset"`
	Prefix    string             `json:"prefix"`
	PrefixLen int                `json:"prefix_len"`
	Cursor    string             `json:"cursor"`
	Groups    map[string]Pending `json:"groups"`
	Seen      time.Time          `json:"seen"`
}

func groups(c Config, s Source, st *Checkpoint, line string, now time.Time) ([]Event, error) {
	if st.Groups == nil {
		st.Groups = map[string]Pending{}
	}
	events := []Event{}
	emit := func(key string, partial bool) {
		p := st.Groups[key]
		e := parse(Config{}, s, p.Raw, p.Since)
		if partial {
			e.Fields["group_completion"] = "timeout_or_size"
		} else {
			e.Fields["group_completion"] = "boundary"
		}
		events = append(events, e)
		delete(st.Groups, key)
	}
	for key, p := range st.Groups {
		if now.Sub(p.Last) > 3*time.Second {
			emit(key, true)
		}
	}
	if line == "" {
		return events, nil
	}
	key := ""
	isEnd := false
	if s.Parser == "auditd" {
		if m := auditID.FindStringSubmatch(line); m != nil {
			key = m[1] + ":" + m[2]
			isEnd = strings.Contains(line, "type=EOE ")
		}
	}
	if s.Multiline != "" || s.Parser == "apt" {
		key = "multiline"
		start := (s.multiline != nil && s.multiline.MatchString(line)) || (s.Parser == "apt" && strings.HasPrefix(line, "Start-Date:"))
		if _, ok := st.Groups[key]; ok && start {
			emit(key, false)
		}
		isEnd = s.Parser == "apt" && strings.HasPrefix(line, "End-Date:")
	}
	if key == "" {
		events = append(events, parse(Config{}, s, line, now))
		return events, nil
	}
	p, ok := st.Groups[key]
	if !ok {
		if len(st.Groups) >= 32 {
			return nil, errors.New("too many interleaved groups; collection paused")
		}
		p = Pending{Since: now}
	}
	if len(p.Raw)+len(line)+1 > maxRecord {
		emit(key, true)
		p = Pending{Since: now}
	}
	if p.Raw != "" {
		p.Raw += "\n"
	}
	p.Raw += line
	p.Last = now
	st.Groups[key] = p
	if isEnd {
		emit(key, false)
	}
	return events, nil
}
func filter(s Source, line string) bool {
	return (s.include == nil || s.include.MatchString(line)) && (s.exclude == nil || !s.exclude.MatchString(line))
}
func collectFile(c Config, s Source, sp *Spool, path string) error {
	f, e := openLogFile(s, path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return e
	}
	if !info.Mode().IsRegular() {
		return errors.New("not a regular log file")
	}
	stat := info.Sys().(*syscall.Stat_t)
	key := fmt.Sprintf("file:%s:%d:%d", s.Name, stat.Dev, stat.Ino)
	var st Checkpoint
	if e = sp.checkpoint(key, &st); e != nil {
		return e
	}
	if st.PrefixLen > 0 {
		b := make([]byte, st.PrefixLen)
		n, _ := f.ReadAt(b, 0)
		h := sha256.Sum256(b[:n])
		if hex.EncodeToString(h[:]) != st.Prefix || info.Size() < st.Offset {
			st = Checkpoint{}
			sp.reject()
		}
	}
	if st.PrefixLen == 0 {
		b := make([]byte, min(64, info.Size()))
		n, _ := f.ReadAt(b, 0)
		if n > 0 {
			h := sha256.Sum256(b[:n])
			st.Prefix = hex.EncodeToString(h[:])
			st.PrefixLen = n
		}
	}
	if _, e = f.Seek(st.Offset, io.SeekStart); e != nil {
		return e
	}
	reader := bufio.NewReaderSize(f, 65536)
	for i := 0; i < 128; i++ {
		line, consumed, oversized, e := boundedLine(reader)
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		next := st
		next.Groups = map[string]Pending{}
		for k, v := range st.Groups {
			next.Groups[k] = v
		}
		next.Offset += consumed
		next.Seen = time.Now().UTC()
		var events []Event
		if oversized {
			if e = sp.reject(); e != nil {
				return e
			}
		} else if filter(s, line) {
			redacted := c.redact(strings.TrimRight(line, "\r\n"))
			if s.Parser == "ossec" {
				redacted = c.redactOSSEC(strings.TrimRight(line, "\r\n"))
			}
			if len(redacted) > maxRecord {
				if e = sp.reject(); e != nil {
					return e
				}
			} else {
				events, e = groups(c, s, &next, redacted, time.Now().UTC())
			}
			if e != nil {
				return e
			}
		}
		for j := range events {
			events[j].Fields["log.file.path"] = path
		}
		if e = sp.addFiltered(s, events, key, next); e != nil {
			return e
		}
		st = next
	}
	events, e := groups(c, s, &st, "", time.Now().UTC())
	if e != nil {
		return e
	}
	for j := range events {
		events[j].Fields["log.file.path"] = path
	}
	return sp.addFiltered(s, events, key, st)
}

type boundedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("journal output exceeds bounded read")
	}
	return b.Buffer.Write(p)
}
func collectJournal(c Config, s Source, sp *Spool) error {
	key := "journal:" + s.Name
	var st Checkpoint
	if e := sp.checkpoint(key, &st); e != nil {
		return e
	}
	args := []string{"--no-pager", "--output=json", "--all", "--lines=+64"}
	if st.Cursor != "" {
		args = append(args, "--after-cursor="+st.Cursor)
	} else {
		args = append(args, "--since="+time.Now().Add(-c.lookback).Format(time.RFC3339))
	}
	for _, unit := range s.Units {
		args = append(args, "--unit="+unit)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/journalctl", args...)
	out := &boundedBuffer{limit: 2 * 1024 * 1024}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		return fmt.Errorf("journal read failed (check permissions/cursor): %w", e)
	}
	scan := bufio.NewScanner(bytes.NewReader(out.Bytes()))
	scan.Buffer(make([]byte, 65536), 2*1024*1024)
	for scan.Scan() {
		var record map[string]json.RawMessage
		if e := json.Unmarshal(scan.Bytes(), &record); e != nil {
			return e
		}
		var cursor, message, ts string
		json.Unmarshal(record["__CURSOR"], &cursor)
		json.Unmarshal(record["MESSAGE"], &message)
		json.Unmarshal(record["__REALTIME_TIMESTAMP"], &ts)
		if cursor == "" {
			return errors.New("journal record lacks cursor")
		}
		next := st
		next.Cursor = cursor
		next.Seen = time.Now().UTC()
		events := []Event{}
		if len(message) > maxRecord {
			sp.reject()
		} else if message != "" && filter(s, message) {
			stamp := time.Now()
			if us, e := strconv.ParseInt(ts, 10, 64); e == nil {
				stamp = time.UnixMicro(us)
			}
			event := parse(c, s, message, stamp)
			event.Fields["journal.cursor"] = cursor
			for _, k := range []string{"_SYSTEMD_UNIT", "_BOOT_ID", "SYSLOG_IDENTIFIER", "PRIORITY", "_PID", "_UID", "_GID", "_COMM", "_HOSTNAME"} {
				var v string
				json.Unmarshal(record[k], &v)
				if len(v) <= 4096 {
					event.Fields[k] = c.redact(v)
				}
			}
			if s.Parser == "syslog" {
				normalizeJournal(&event)
			}
			if len(event.Raw) > maxRecord {
				if err := sp.reject(); err != nil {
					return err
				}
			} else {
				events = append(events, event)
			}
		}
		if e := sp.addFiltered(s, events, key, next); e != nil {
			return e
		}
		st = next
	}
	return scan.Err()
}
func collect(c Config, s Source, sp *Spool) error {
	if s.Kind == "journal" {
		return collectJournal(c, s, sp)
	}
	paths := map[string]bool{}
	for _, pattern := range s.Paths {
		matches, e := filepath.Glob(pattern)
		if e != nil {
			return e
		}
		for _, p := range matches {
			if !strings.HasSuffix(p, ".gz") {
				paths[p] = true
			}
		}
	}
	if len(paths) > 256 {
		return errors.New("too many matching files")
	}
	if len(paths) == 0 {
		return errors.New("no matching log files")
	}
	list := []string{}
	for p := range paths {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool {
		a, ea := os.Stat(list[i])
		b, eb := os.Stat(list[j])
		if ea != nil || eb != nil {
			return list[i] < list[j]
		}
		return a.ModTime().Before(b.ModTime())
	})
	for _, p := range list {
		if e := collectFile(c, s, sp, p); e != nil {
			return e
		}
	}
	return nil
}

// Consume an oversized complete line without allocating its full contents.
// An incomplete line never advances the durable checkpoint.
func boundedLine(r *bufio.Reader) (string, int64, bool, error) {
	var b strings.Builder
	var size int64
	oversized := false
	for {
		chunk, err := r.ReadSlice('\n')
		size += int64(len(chunk))
		if size > maxRecord {
			oversized = true
			b.Reset()
		} else if !oversized {
			b.Write(chunk)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return b.String(), size, oversized, err
	}
}
