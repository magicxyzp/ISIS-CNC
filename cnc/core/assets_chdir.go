package core

import (
	"os"
	"path/filepath"
)

// ChdirToProjectWithAssets sets the process working directory to the folder that
// contains assets/config.json (current dir, next to the executable, or parents).
// This fixes empty banners and unreplaced <<$...>> tokens when the binary is run from another cwd.
func ChdirToProjectWithAssets() bool {
	if fileExists(filepath.Join("assets", "config.json")) {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(exe))
	if err != nil {
		dir = filepath.Dir(exe)
	}
	for _, c := range []string{dir, filepath.Join(dir, ".."), filepath.Join(dir, "..", "..")} {
		root := filepath.Clean(c)
		if fileExists(filepath.Join(root, "assets", "config.json")) {
			_ = os.Chdir(root)
			return true
		}
	}
	return false
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}
