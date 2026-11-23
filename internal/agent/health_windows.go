//go:build windows

package agent

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func defaultDiskPath() string { return `C:\` }

// memoryStatusEx is MEMORYSTATUSEX.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var procGlobalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// readResources reads memory in use (GlobalMemoryStatusEx) and disk usage
// (GetDiskFreeSpaceEx). Windows has no load average: CPU is not measured.
func readResources(paths []string) (cpu, mem float64, disk map[string]float64, err error) {
	cpu, mem = -1, -1
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r != 0 {
		mem = float64(ms.MemoryLoad)
	}
	disk = map[string]float64{}
	for _, p := range paths {
		ptr, err := windows.UTF16PtrFromString(p)
		if err != nil {
			continue
		}
		var avail, total, free uint64
		if windows.GetDiskFreeSpaceEx(ptr, &avail, &total, &free) != nil || total == 0 {
			continue
		}
		disk[p] = float64(total-free) / float64(total) * 100
	}
	return cpu, mem, disk, nil
}

// serviceRunning asks the service control manager.
func serviceRunning(ctx context.Context, name string) (bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return false, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return false, err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return false, err
	}
	return st.State == svc.Running, nil
}

// checkCommandFile allows only regular script or program files directly in
// the health.d directory (its ACL is set up by the install script).
func checkCommandFile(dir, path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if filepath.Dir(path) != filepath.Clean(dir) {
		return errors.New("outside health.d")
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".ps1", ".cmd", ".bat", ".exe":
		return nil
	}
	return errors.New("only .ps1, .cmd, .bat or .exe files")
}

func commandFor(ctx context.Context, path string) *exec.Cmd {
	if strings.EqualFold(filepath.Ext(path), ".ps1") {
		return exec.CommandContext(ctx, powershell(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", path)
	}
	return exec.CommandContext(ctx, path)
}

// freeBytes is the free space on the system drive, -1 when unknown.
func freeBytes() int64 {
	ptr, err := windows.UTF16PtrFromString(defaultDiskPath())
	if err != nil {
		return -1
	}
	var avail, total, free uint64
	if windows.GetDiskFreeSpaceEx(ptr, &avail, &total, &free) != nil {
		return -1
	}
	return int64(avail)
}
