package models

import "time"

type Report struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	TeamID    string    `json:"teamId"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	Data      any       `json:"data"`
}
