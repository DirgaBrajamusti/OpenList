package ddrv

import (
	"time"
)

type Item struct {
	ID     string    `json:"id"`
	Name   string    `json:"Name"`
	IsDir  bool      `json:"dir"`
	Size   int       `json:"size,omitempty"`
	Parent string    `json:"parent"`
	MTime  time.Time `json:"mtime"`
}

type Response struct {
	Message string `json:"message"`
	Data    struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		IsDir bool   `json:"dir"`
		MTime string `json:"mtime"`
		Files []Item `json:"files"`
	} `json:"data"`
}
