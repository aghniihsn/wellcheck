package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Team struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"id"`
	Name        string               `bson:"name" json:"name"`
	Description string               `bson:"description,omitempty" json:"description,omitempty"`
	Members     []primitive.ObjectID `bson:"members" json:"members"`
	Lead        primitive.ObjectID   `bson:"lead" json:"lead"`
	CreatedAt   time.Time            `bson:"createdAt" json:"createdAt"`
}
