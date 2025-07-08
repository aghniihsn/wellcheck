package routes

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"backend/models"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func RegisterCheckinRoutes(app *fiber.App, db *mongo.Database) {
	jwtSecret := []byte(os.Getenv("JWT_SECRET")) // Pindahkan ke dalam fungsi agar selalu update
	authRequired := func(c *fiber.Ctx) error {
		tokenStr := c.Get("Authorization")
		if tokenStr == "" || len(tokenStr) < 8 {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid token"})
		}
		tokenStr = tokenStr[7:] // Bearer ...
		token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			// Print pesan error JWT parse yang jelas
			fmt.Println("JWT parse error:", err)
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
		}
		c.Locals("userId", claims["id"])
		c.Locals("userRole", claims["role"])
		return c.Next()
	}

	// GET /api/checkins - get all checkins (for manager, return all; for member, only their own)
	app.Get("/api/checkins", authRequired, func(c *fiber.Ctx) error {
		userId, ok := c.Locals("userId").(string)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		userRole, _ := c.Locals("userRole").(string)
		var filter bson.M
		if userRole == "manager" || userRole == "project_manager" {
			filter = bson.M{} // all data
		} else {
			objId, _ := primitive.ObjectIDFromHex(userId)
			filter = bson.M{"userId": objId}
		}
		cur, err := db.Collection("checkins").Find(context.Background(), filter)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		var checkins []models.Checkin
		if err := cur.All(context.Background(), &checkins); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(checkins)
	})

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
		status := "present"
		checkin := models.Checkin{
			ID:          primitive.NewObjectID(),
			UserID:      objId,
			Type:        req.Type,
			Mood:        req.Mood,
			SelfieURL:   req.SelfieImage, // base64 string, bisa diubah ke URL jika upload file
			Description: req.Description,
			CreatedAt:   time.Now(),
			FaceResult:  req.FaceData,
			Status:      status,
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
