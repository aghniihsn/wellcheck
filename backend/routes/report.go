package routes

import (
	"backend/models"
	"context"
	"net/http"
	"os"

	"encoding/csv"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

func RegisterReportRoutes(app *fiber.App, db *mongo.Database) {
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

	reportGroup := app.Group("/reports", authRequired)

	// Endpoint download report sebagai CSV
	reportGroup.Get("/:id/download", func(c *fiber.Ctx) error {
		reportID := c.Params("id")
		var report models.Report
		err := db.Collection("reports").FindOne(context.Background(), bson.M{"id": reportID}).Decode(&report)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "Report not found"})
		}
		summary, ok := report.Data.(map[string]interface{})
		if !ok {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Invalid report data"})
		}
		var moodCount map[string]int
		if raw, ok := summary["moodCount"]; ok {
			switch v := raw.(type) {
			case map[string]int:
				moodCount = v
			case map[string]interface{}:
				moodCount = map[string]int{}
				for k, val := range v {
					switch vv := val.(type) {
					case int:
						moodCount[k] = vv
					case int32:
						moodCount[k] = int(vv)
					case int64:
						moodCount[k] = int(vv)
					case float64:
						moodCount[k] = int(vv)
					}
				}
			}
		}
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", "attachment;filename=report_"+reportID+".csv")
		writer := csv.NewWriter(c)
		writer.Write([]string{"Mood", "Count"})
		for mood, count := range moodCount {
			writer.Write([]string{mood, strconv.Itoa(count)})
		}
		writer.Flush()
		return nil
	})
}
