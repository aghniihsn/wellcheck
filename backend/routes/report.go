package routes

import (
	"backend/models"
	"context"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

func RegisterReportRoutes(app *fiber.App, db *mongo.Database) {
	// JWT & Auth middleware
	jwtSecret := []byte("your_jwt_secret") // Ganti dengan os.Getenv jika perlu
	authRequired := func(c *fiber.Ctx) error {
		tokenStr := c.Get("Authorization")
		if tokenStr == "" || len(tokenStr) < 8 {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid token"})
		}
		tokenStr = tokenStr[7:]
		// NOTE: Import "github.com/golang-jwt/jwt/v5" jika belum
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}
		return c.Next()
	}

	reportGroup := app.Group("/api/reports", authRequired)

	// Endpoint untuk generate dan simpan report
	reportGroup.Post("/generate", func(c *fiber.Ctx) error {
		// Ambil user dari token
		tokenStr := c.Get("Authorization")
		if tokenStr == "" || len(tokenStr) < 8 {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid token"})
		}
		tokenStr = tokenStr[7:]
		token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token claims"})
		}
		userId, _ := claims["id"].(string)

		var req struct {
			Title  string      `json:"title"`
			TeamID string      `json:"teamId"`
			Type   string      `json:"type"`
			Period string      `json:"period"`
			Data   interface{} `json:"data"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request body"})
		}
		report := models.Report{
			ID:        primitive.NewObjectID().Hex(),
			Title:     req.Title,
			TeamID:    req.TeamID,
			CreatedBy: userId,
			CreatedAt: time.Now(),
			Data: map[string]interface{}{
				"type":   req.Type,
				"period": req.Period,
				"data":   req.Data,
			},
		}
		_, err = db.Collection("reports").InsertOne(context.Background(), report)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to save report"})
		}
		return c.JSON(report)
	})

	// Endpoint untuk mengambil semua report (PUBLIC)
	app.Get("/api/reports", func(c *fiber.Ctx) error {
		cur, err := db.Collection("reports").Find(context.Background(), bson.M{})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		var reports []models.Report
		if err := cur.All(context.Background(), &reports); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(reports)
	})

	// Endpoint untuk mengambil monthly report absen & mood per team
	// GET /api/reports/monthly?teamId=...&month=YYYY-MM
	reportGroup.Get("/monthly", func(c *fiber.Ctx) error {
		teamId := c.Query("teamId")
		month := c.Query("month") // format: YYYY-MM
		if teamId == "" || month == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "teamId and month required"})
		}
		// Parse month
		t, err := time.Parse("2006-01", month)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid month format"})
		}
		start := t
		end := t.AddDate(0, 1, 0)
		// Cari semua user di team
		teamObjId, err := primitive.ObjectIDFromHex(teamId)
		if err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid teamId"})
		}
		var team models.Team
		err = db.Collection("teams").FindOne(context.Background(), bson.M{"_id": teamObjId}).Decode(&team)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Team not found"})
		}
		// Ambil semua checkin team di bulan tsb
		userIds := append([]primitive.ObjectID{}, team.Members...)
		filter := bson.M{"userId": bson.M{"$in": userIds}, "createdAt": bson.M{"$gte": start, "$lt": end}}
		cur, err := db.Collection("checkins").Find(context.Background(), filter)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		var checkins []models.Checkin
		if err := cur.All(context.Background(), &checkins); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		// Rekap absen & mood
		report := map[string]interface{}{}
		absen := map[string]map[string]string{} // userId -> tanggal -> status
		mood := map[string]map[string]string{}  // userId -> tanggal -> mood
		for _, c := range checkins {
			uid := c.UserID.Hex()
			tgl := c.CreatedAt.Format("2006-01-02")
			if absen[uid] == nil {
				absen[uid] = map[string]string{}
			}
			if mood[uid] == nil {
				mood[uid] = map[string]string{}
			}
			absen[uid][tgl] = c.Status
			mood[uid][tgl] = c.Mood
		}
		report["absen"] = absen
		report["mood"] = mood
		return c.JSON(report)
	})

	// ...existing code...
}
