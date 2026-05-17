package agent

import (
	"io/fs"
	"reflect"
	"time"
)

type fileTimeEvidence struct {
	ModTime          time.Time
	StatusChangeTime time.Time
	BirthTime        time.Time
}

type fileEventTimeDecision struct {
	EventTime  time.Time
	Source     string
	Confidence string
	Backdated  bool
	Future     bool
	Note       string
}

const fileTimestampSkewTolerance = 2 * time.Second

func fileTimestampEvidence(info fs.FileInfo) fileTimeEvidence {
	evidence := fileTimeEvidence{}
	if info == nil {
		return evidence
	}
	evidence.ModTime = info.ModTime().UTC()
	sys := reflect.ValueOf(info.Sys())
	if !sys.IsValid() {
		return evidence
	}
	if sys.Kind() == reflect.Pointer {
		if sys.IsNil() {
			return evidence
		}
		sys = sys.Elem()
	}
	if sys.Kind() != reflect.Struct {
		return evidence
	}
	evidence.StatusChangeTime = firstStructTime(sys, "Ctim", "Ctimespec")
	evidence.BirthTime = firstStructTime(sys, "Birthtim", "Btim", "Birthtimespec", "CreationTime")
	return evidence
}

func firstStructTime(value reflect.Value, names ...string) time.Time {
	for _, name := range names {
		field := value.FieldByName(name)
		if !field.IsValid() {
			continue
		}
		if t := timeFromStructTime(field); !t.IsZero() {
			return t.UTC()
		}
	}
	return time.Time{}
}

func timeFromStructTime(value reflect.Value) time.Time {
	if value.Kind() == reflect.Pointer {
		if value.IsNil() {
			return time.Time{}
		}
		value = value.Elem()
	}
	if value.Kind() != reflect.Struct {
		return time.Time{}
	}
	if secField := value.FieldByName("Sec"); secField.IsValid() {
		sec := reflectSignedInt(secField)
		if sec <= 0 {
			return time.Time{}
		}
		nsec := reflectSignedInt(value.FieldByName("Nsec"))
		return time.Unix(sec, nsec).UTC()
	}
	if highField := value.FieldByName("HighDateTime"); highField.IsValid() {
		high := reflectUnsignedInt(highField)
		low := reflectUnsignedInt(value.FieldByName("LowDateTime"))
		ticks := (high << 32) | low
		if ticks == 0 || ticks <= 116444736000000000 {
			return time.Time{}
		}
		return time.Unix(0, int64(ticks-116444736000000000)*100).UTC()
	}
	return time.Time{}
}

func reflectSignedInt(value reflect.Value) int64 {
	if !value.IsValid() {
		return 0
	}
	switch value.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return int64(value.Uint())
	default:
		return 0
	}
}

func reflectUnsignedInt(value reflect.Value) uint64 {
	if !value.IsValid() {
		return 0
	}
	switch value.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return value.Uint()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		signed := value.Int()
		if signed < 0 {
			return 0
		}
		return uint64(signed)
	default:
		return 0
	}
}

func fileEventTiming(eventType string, current fileState, previous fileState) fileEventTimeDecision {
	observedAt := current.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	observedAt = observedAt.UTC()
	switch eventType {
	case "file.deleted":
		return fileEventTimeDecision{
			EventTime:  observedAt,
			Source:     "observed_at",
			Confidence: "observed",
			Note:       "deletion time is the scan time because the file no longer exists",
		}
	case "file.created":
		return fileCreatedTiming(current, observedAt)
	case "file.modified":
		return fileModifiedTiming(current, previous, observedAt)
	default:
		return fileObservedTiming(observedAt)
	}
}

func fileCreatedTiming(current fileState, observedAt time.Time) fileEventTimeDecision {
	sourceTime := firstNonZeroTime(current.BirthTime, current.StatusChangeTime, current.ModTime, observedAt)
	source := fileTimeSource(current, sourceTime)
	decision := fileEventTimeDecision{EventTime: sourceTime, Source: source, Confidence: fileTimeConfidence(source)}
	switch {
	case !current.BirthTime.IsZero() && current.BirthTime.After(current.ModTime.Add(fileTimestampSkewTolerance)):
		decision.EventTime = current.BirthTime
		decision.Source = "birth_time"
		decision.Confidence = "strong"
		decision.Backdated = true
		decision.Note = "file birth time is newer than modification time; this can indicate copied or backdated content"
	case current.StatusChangeTime.After(current.ModTime.Add(fileTimestampSkewTolerance)):
		decision.EventTime = current.StatusChangeTime
		decision.Source = "status_change_time"
		decision.Confidence = "strong"
		decision.Backdated = true
		decision.Note = "file modification time is older than metadata change time; this can indicate copied or backdated content"
	}
	return guardFutureFileTime(decision, observedAt)
}

func fileModifiedTiming(current fileState, previous fileState, observedAt time.Time) fileEventTimeDecision {
	sourceTime := firstNonZeroTime(current.ModTime, current.StatusChangeTime, observedAt)
	source := fileTimeSource(current, sourceTime)
	decision := fileEventTimeDecision{EventTime: sourceTime, Source: source, Confidence: fileTimeConfidence(source)}
	switch {
	case current.SHA256 != "" && previous.SHA256 != "" && current.SHA256 != previous.SHA256 &&
		!previous.ModTime.IsZero() && !current.ModTime.After(previous.ModTime.Add(fileTimestampSkewTolerance)):
		decision.EventTime = observedAt
		decision.Source = "observed_at"
		decision.Confidence = "observed"
		decision.Backdated = true
		decision.Note = "content hash changed while modification time did not advance"
	case current.StatusChangeTime.After(current.ModTime.Add(fileTimestampSkewTolerance)) &&
		(previous.ModTime.IsZero() || !current.ModTime.After(previous.ModTime.Add(fileTimestampSkewTolerance))):
		decision.EventTime = current.StatusChangeTime
		decision.Source = "status_change_time"
		decision.Confidence = "strong"
		decision.Backdated = true
		decision.Note = "content changed while modification time did not advance; metadata time is used as the safer occurrence time"
	}
	return guardFutureFileTime(decision, observedAt)
}

func fileObservedTiming(observedAt time.Time) fileEventTimeDecision {
	return fileEventTimeDecision{
		EventTime:  observedAt,
		Source:     "observed_at",
		Confidence: "observed",
	}
}

func guardFutureFileTime(decision fileEventTimeDecision, observedAt time.Time) fileEventTimeDecision {
	if decision.EventTime.IsZero() {
		return fileObservedTiming(observedAt)
	}
	if decision.EventTime.After(observedAt.Add(fileTimestampSkewTolerance)) {
		decision.EventTime = observedAt
		decision.Source = "observed_at"
		decision.Confidence = "observed"
		decision.Future = true
		decision.Note = "source filesystem timestamp is in the future relative to scan time"
	}
	return decision
}

func fileTimeSource(current fileState, value time.Time) string {
	switch {
	case !current.BirthTime.IsZero() && current.BirthTime.Equal(value):
		return "birth_time"
	case !current.StatusChangeTime.IsZero() && current.StatusChangeTime.Equal(value):
		return "status_change_time"
	case !current.ModTime.IsZero() && current.ModTime.Equal(value):
		return "mod_time"
	default:
		return "observed_at"
	}
}

func fileTimeConfidence(source string) string {
	switch source {
	case "birth_time", "status_change_time":
		return "strong"
	case "mod_time":
		return "source"
	default:
		return "observed"
	}
}

func firstNonZeroTime(values ...time.Time) time.Time {
	for _, value := range values {
		if !value.IsZero() {
			return value.UTC()
		}
	}
	return time.Time{}
}

func addFileTimePayload(payload map[string]any, key string, value time.Time) {
	if value.IsZero() {
		return
	}
	payload[key] = value.UTC().Format(time.RFC3339Nano)
}
