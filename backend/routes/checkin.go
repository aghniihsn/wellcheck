package routes

import (
	"context"
	"net/http"
	"time"

	"backend/models"

	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func RegisterCheckinRoutes(app *fiber.App, db *mongo.Database) {
	authRequired := func(c *fiber.Ctx) error {
		tokenStr := c.Get("Authorization")
		if tokenStr == "" || len(tokenStr) < 8 {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid token"})
		}
		tokenStr = tokenStr[7:] // Bearer ...
		// ...parse JWT sama seperti di user.go...
		return c.Next()
	}

	app.Post("/api/checkins", authRequired, func(c *fiber.Ctx) error {
		var req struct {
			Type        string             `json:"type"`
			Mood        string             `json:"mood"`
			Description string             `json:"description"`
			SelfieImage string             `json:"selfieImage"`
			FaceData    *models.FaceResult `json:"faceData"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		userId, ok := c.Locals("userId").(string)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		objId, _ := primitive.ObjectIDFromHex(userId)
		checkin := models.Checkin{
			ID:          primitive.NewObjectID(),
			UserID:      objId,
			Type:        req.Type,
			Mood:        req.Mood,
			SelfieURL:   req.SelfieImage, // base64 string, bisa diubah ke URL jika upload file
			Description: req.Description,
			CreatedAt:   time.Now(),
			FaceResult:  req.FaceData,
		}
		_, err := db.Collection("checkins").InsertOne(context.Background(), checkin)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusCreated).JSON(checkin)
	})

	app.Get("/api/checkins/today", authRequired, func(c *fiber.Ctx) error {
		userId, ok := c.Locals("userId").(string)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		objId, _ := primitive.ObjectIDFromHex(userId)
		start := time.Now().Truncate(24 * time.Hour)
		end := start.Add(24 * time.Hour)
		cur, err := db.Collection("checkins").Find(context.Background(), bson.M{"userId": objId, "createdAt": bson.M{"$gte": start, "$lt": end}})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		var checkins []models.Checkin
		if err := cur.All(context.Background(), &checkins); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(checkins)
	})
}
