package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Project struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Name        string               `bson:"name" json:"name"`
	Description string               `bson:"description,omitempty" json:"description,omitempty"`
	StartDate   *time.Time           `bson:"startDate,omitempty" json:"startDate,omitempty"`
	EndDate     *time.Time           `bson:"endDate,omitempty" json:"endDate,omitempty"`
	Teams       []primitive.ObjectID `bson:"teams" json:"teams"`
	CreatedAt   time.Time            `bson:"createdAt" json:"createdAt"`
}
