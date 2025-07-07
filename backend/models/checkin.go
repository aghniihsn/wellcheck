package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Checkin struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID      primitive.ObjectID `bson:"userId" json:"userId"`
	Type        string             `bson:"type" json:"type"` // checkin/checkout
	Mood        string             `bson:"mood" json:"mood"`
	SelfieURL   string             `bson:"selfieUrl" json:"selfieUrl"`
	Description string             `bson:"description" json:"description"`
	CreatedAt   time.Time          `bson:"createdAt" json:"createdAt"`
	FaceResult  *FaceResult        `bson:"faceResult,omitempty" json:"faceResult,omitempty"`
	Status      string             `bson:"status" json:"status"` // present/absent
}

type FaceResult struct {
	Gender     string  `bson:"gender" json:"gender"`
	Age        float64 `bson:"age" json:"age"`
	Expression string  `bson:"expression" json:"expression"`
}
