package routes

import (
	"context"
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

func RegisterTeamRoutes(app *fiber.App, db *mongo.Database) {
	jwtSecret := []byte(os.Getenv("JWT_SECRET"))
	authRequired := func(c *fiber.Ctx) error {
		tokenStr := c.Get("Authorization")
		if tokenStr == "" || len(tokenStr) < 8 {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid token"})
		}
		tokenStr = tokenStr[7:]
		token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
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

	teamCol := db.Collection("teams")

	app.Get("/api/teams", authRequired, func(c *fiber.Ctx) error {
		ctx := context.Background()
		cur, err := teamCol.Find(ctx, bson.M{})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		var teams []models.Team
		if err := cur.All(ctx, &teams); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(teams)
	})

	app.Get("/api/teams/:id", authRequired, func(c *fiber.Ctx) error {
		id, err := primitive.ObjectIDFromHex(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid team id"})
		}
		var team models.Team
		err = teamCol.FindOne(context.Background(), bson.M{"_id": id}).Decode(&team)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Team not found"})
		}
		return c.JSON(team)
	})

	app.Post("/api/teams", authRequired, func(c *fiber.Ctx) error {
		var req struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Members     []string `json:"members"`
			Lead        string   `json:"lead"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		memberObjIDs := []primitive.ObjectID{}
		for _, m := range req.Members {
			objID, err := primitive.ObjectIDFromHex(m)
			if err == nil {
				memberObjIDs = append(memberObjIDs, objID)
			}
		}
		leadObjID, _ := primitive.ObjectIDFromHex(req.Lead)
		team := models.Team{
			ID:          primitive.NewObjectID(),
			Name:        req.Name,
			Description: req.Description,
			Members:     memberObjIDs,
			Lead:        leadObjID,
			CreatedAt:   time.Now(),
		}
		_, err := teamCol.InsertOne(context.Background(), team)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(team)
	})

	app.Put("/api/teams/:id", authRequired, func(c *fiber.Ctx) error {
		id, err := primitive.ObjectIDFromHex(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid team id"})
		}
		var req struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			Members     []string `json:"members"`
			Lead        string   `json:"lead"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		memberObjIDs := []primitive.ObjectID{}
		for _, m := range req.Members {
			objID, err := primitive.ObjectIDFromHex(m)
			if err == nil {
				memberObjIDs = append(memberObjIDs, objID)
			}
		}
		leadObjID, _ := primitive.ObjectIDFromHex(req.Lead)
		update := bson.M{
			"name":        req.Name,
			"description": req.Description,
			"members":     memberObjIDs,
			"lead":        leadObjID,
		}
		_, err = teamCol.UpdateOne(context.Background(), bson.M{"_id": id}, bson.M{"$set": update})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"success": true})
	})

	app.Delete("/api/teams/:id", authRequired, func(c *fiber.Ctx) error {
		id, err := primitive.ObjectIDFromHex(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid team id"})
		}
		_, err = teamCol.DeleteOne(context.Background(), bson.M{"_id": id})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"success": true})
	})
}
