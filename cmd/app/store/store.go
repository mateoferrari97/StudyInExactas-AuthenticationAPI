package store

import (
	"encoding/gob"

	"github.com/gorilla/sessions"
)

const _defaultFileSystemStorePath = ""

func NewFileSystemStore() *sessions.FilesystemStore {
	gob.Register(map[string]interface{}{})
	return sessions.NewFilesystemStore(_defaultFileSystemStorePath, []byte("something-very-secret"))
}
