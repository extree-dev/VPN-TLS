//go:build windows

package main

import (
	"encoding/json"
	"os"
	"sync"
)

// Settings — настройки приложения (settings.json в папке данных).
type Settings struct {
	AutoConnect bool `json:"autoConnect"` // подключаться при запуске программы
	CloseToTray bool `json:"closeToTray"` // крестик сворачивает в трей, а не закрывает
	Notify      bool `json:"notify"`      // уведомления о подключении и обрывах
}

type settingsStore struct {
	path string
	mu   sync.Mutex
	s    Settings
}

func loadSettings(path string) *settingsStore {
	st := &settingsStore{path: path, s: Settings{CloseToTray: true, Notify: true}}
	if data, err := os.ReadFile(path); err == nil {
		json.Unmarshal(data, &st.s)
	}
	return st
}

func (st *settingsStore) get() Settings {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.s
}

func (st *settingsStore) set(s Settings) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.s = s
	data, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(st.path, data, 0o600)
}
