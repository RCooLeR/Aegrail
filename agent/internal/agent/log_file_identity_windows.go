package agent

import (
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

func logFileIdentity(file *os.File, _ fs.FileInfo) string {
	if file == nil {
		return ""
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return ""
	}
	index := uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	return fmt.Sprintf("windows:%08x:%016x", info.VolumeSerialNumber, index)
}
