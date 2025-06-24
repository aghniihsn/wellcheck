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

func RegisterProjectRoutes(app *fiber.App, db *mongo.Database) {
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

	projectCol := db.Collection("projects")

	app.Get("/api/projects", authRequired, func(c *fiber.Ctx) error {
		ctx := context.Background()
		cur, err := projectCol.Find(ctx, bson.M{})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		var projects []models.Project
		if err := cur.All(ctx, &projects); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(projects)
	})

	app.Get("/api/projects/:id", authRequired, func(c *fiber.Ctx) error {
		id, err := primitive.ObjectIDFromHex(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid project id"})
		}
		var project models.Project
		err = projectCol.FindOne(context.Background(), bson.M{"_id": id}).Decode(&project)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Project not found"})
		}
		return c.JSON(project)
	})

	// POST /api/projects
	app.Post("/api/projects", authRequired, func(c *fiber.Ctx) error {
		var req struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			StartDate   string   `json:"startDate"`
			EndDate     string   `json:"endDate"`
			Teams       []string `json:"teams"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var startDatePtr, endDatePtr *time.Time
		if req.StartDate != "" {
			dt, err := time.Parse("2006-01-02", req.StartDate)
			if err == nil {
				startDatePtr = &dt
			}
		}
		if req.EndDate != "" {
			dt, err := time.Parse("2006-01-02", req.EndDate)
			if err == nil {
				endDatePtr = &dt
			}
		}
		teamObjIDs := []primitive.ObjectID{}
		for _, t := range req.Teams {
			objID, err := primitive.ObjectIDFromHex(t)
			if err == nil {
				teamObjIDs = append(teamObjIDs, objID)
			}
		}
		project := models.Project{
			ID:          primitive.NewObjectID(),
			Name:        req.Name,
			Description: req.Description,
			StartDate:   startDatePtr,
			EndDate:     endDatePtr,
			Teams:       teamObjIDs,
			CreatedAt:   time.Now(),
		}
		_, err := projectCol.InsertOne(context.Background(), project)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(project)
	})

	// PUT /api/projects/:id
	app.Put("/api/projects/:id", authRequired, func(c *fiber.Ctx) error {
		id, err := primitive.ObjectIDFromHex(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid project id"})
		}
		var req struct {
			Name        string   `json:"name"`
			Description string   `json:"description"`
			StartDate   string   `json:"startDate"`
			EndDate     string   `json:"endDate"`
			Teams       []string `json:"teams"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		update := bson.M{
			"name":        req.Name,
			"description": req.Description,
		}
		if req.StartDate != "" {
			dt, err := time.Parse("2006-01-02", req.StartDate)
			if err == nil {
				update["startDate"] = dt
			}
		}
		if req.EndDate != "" {
			dt, err := time.Parse("2006-01-02", req.EndDate)
			if err == nil {
				update["endDate"] = dt
			}
		}
		if req.Teams != nil {
			teamObjIDs := []primitive.ObjectID{}
			for _, t := range req.Teams {
				objID, err := primitive.ObjectIDFromHex(t)
				if err == nil {
					teamObjIDs = append(teamObjIDs, objID)
				}
			}
			update["teams"] = teamObjIDs
		}
		_, err = projectCol.UpdateOne(context.Background(), bson.M{"_id": id}, bson.M{"$set": update})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"success": true})
	})

	app.Delete("/api/projects/:id", authRequired, func(c *fiber.Ctx) error {
		id, err := primitive.ObjectIDFromHex(c.Params("id"))
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid project id"})
		}
		_, err = projectCol.DeleteOne(context.Background(), bson.M{"_id": id})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"success": true})
	})

	// GET /api/projects-with-team
	app.Get("/api/projects-with-team", authRequired, func(c *fiber.Ctx) error {
		ctx := context.Background()
		projectCol := db.Collection("projects")

		cur, err := projectCol.Find(ctx, bson.M{})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		var projects []models.Project
		if err := cur.All(ctx, &projects); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}

		var result []fiber.Map
		for _, p := range projects {
			result = append(result, fiber.Map{
				"id":          p.ID.Hex(),
				"name":        p.Name,
				"description": p.Description,
				"startDate":   p.StartDate,
				"endDate":     p.EndDate,
				"createdAt":   p.CreatedAt,
			})
		}
		return c.JSON(result)
	})
}
