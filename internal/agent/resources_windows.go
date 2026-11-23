//go:build windows

package agent

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"

	"netio.patchman/internal/protocol"
)

// ReadResources reads memory and the page file (GlobalMemoryStatusEx) and
// the usage of every fixed drive. Windows has no load average.
func ReadResources() protocol.Resources {
	r := protocol.Resources{CPUs: runtime.NumCPU()}
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	if ok, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); ok != 0 {
		r.MemoryTotal, r.MemoryAvailable = int64(ms.TotalPhys), int64(ms.AvailPhys)
		// The commit limit counts physical memory and the page files.
		if ms.TotalPageFile > ms.TotalPhys {
			r.SwapTotal = int64(ms.TotalPageFile - ms.TotalPhys)
			if ms.AvailPageFile > ms.AvailPhys {
				r.SwapFree = min(int64(ms.AvailPageFile-ms.AvailPhys), r.SwapTotal)
			}
		}
	}
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return r
	}
	for i := 0; i < 26 && len(r.Disks) < protocol.MaxDisks; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		ptr, err := windows.UTF16PtrFromString(root)
		if err != nil || windows.GetDriveType(ptr) != windows.DRIVE_FIXED {
			continue
		}
		var avail, total, free uint64
		if windows.GetDiskFreeSpaceEx(ptr, &avail, &total, &free) != nil || total == 0 {
			continue
		}
		r.Disks = append(r.Disks, protocol.DiskUsage{Path: root, Total: int64(total), Used: int64(total - free), Available: int64(avail)})
	}
	return r
}
