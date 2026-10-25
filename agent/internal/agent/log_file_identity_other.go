//go:build !windows

package agent

import (
	"fmt"
	"io/fs"
	"os"
	"reflect"
)

func logFileIdentity(_ *os.File, info fs.FileInfo) string {
	if info == nil || info.Sys() == nil {
		return ""
	}
	stat := reflect.ValueOf(info.Sys())
	if stat.Kind() == reflect.Pointer {
		if stat.IsNil() {
			return ""
		}
		stat = stat.Elem()
	}
	if stat.Kind() != reflect.Struct {
		return ""
	}
	device, deviceOK := numericStatField(stat, "Dev")
	inode, inodeOK := numericStatField(stat, "Ino")
	if !deviceOK || !inodeOK {
		return ""
	}
	return fmt.Sprintf("unix:%x:%x", device, inode)
}

func numericStatField(stat reflect.Value, name string) (uint64, bool) {
	field := stat.FieldByName(name)
	if !field.IsValid() {
		return 0, false
	}
	switch field.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return uint64(field.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return field.Uint(), true
	default:
		return 0, false
	}
}
