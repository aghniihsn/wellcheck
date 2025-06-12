// main.go
package main

import (
	"backend/routes"
	"context"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoClient *mongo.Client

func main() {
	// Load .env
	_ = godotenv.Load()

	app := fiber.New()
	app.Use(cors.New())

	// MongoDB connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(os.Getenv("MONGODB_URI")))
	if err != nil {
		log.Fatal(err)
	}
	mongoClient = client
	db := client.Database("wellness") // Ganti sesuai nama database Anda

	routes.RegisterCheckinRoutes(app, db)
	routes.RegisterUserRoutes(app, db)

	app.Get("/api/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})

	log.Println("Server running on :3001")
	log.Fatal(app.Listen(":3001"))
}
