package routes

import (
	"backend/models"
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

func RegisterUserRoutes(app *fiber.App, db *mongo.Database) {
	jwtSecret := []byte(os.Getenv("JWT_SECRET")) // Pindahkan ke dalam fungsi agar selalu update
	app.Post("/api/auth/register", func(c *fiber.Ctx) error {
		var req struct {
			Name     string `json:"name"`
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		// Debug log
		log.Printf("Register body: %+v", req)
		if req.Name == "" || req.Email == "" || req.Password == "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Name, email, and password are required"})
		}
		// Cek email sudah terdaftar
		count, _ := db.Collection("users").CountDocuments(context.Background(), bson.M{"email": req.Email})
		if count > 0 {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Email already registered"})
		}
		// Hash password
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Hash error: %v", err)
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
		}
		user := models.User{
			ID:       primitive.NewObjectID(),
			Name:     req.Name,
			Email:    req.Email,
			Password: string(hash),
			Role:     "member",
		}
		_, err = db.Collection("users").InsertOne(context.Background(), user)
		if err != nil {
			log.Printf("Insert error: %v", err)
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(http.StatusCreated).JSON(fiber.Map{"id": user.ID.Hex(), "name": user.Name, "email": user.Email, "role": user.Role})
	})

	app.Post("/api/auth/login", func(c *fiber.Ctx) error {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := c.BodyParser(&req); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		var user models.User
		err := db.Collection("users").FindOne(context.Background(), bson.M{"email": req.Email}).Decode(&user)
		if err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid email or password"})
		}
		// Generate JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":    user.ID.Hex(),
			"name":  user.Name,
			"email": user.Email,
			"role":  user.Role,
			"exp":   time.Now().Add(24 * time.Hour).Unix(),
		})
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
		}
		return c.JSON(fiber.Map{"token": tokenString, "user": fiber.Map{"id": user.ID.Hex(), "name": user.Name, "email": user.Email, "role": user.Role}})
	})

	// Middleware JWT
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

	app.Get("/api/user/profile", authRequired, func(c *fiber.Ctx) error {
		userId, ok := c.Locals("userId").(string)
		if !ok {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
		}
		objId, _ := primitive.ObjectIDFromHex(userId)
		var user models.User
		err := db.Collection("users").FindOne(context.Background(), bson.M{"_id": objId}).Decode(&user)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
		}
		return c.JSON(fiber.Map{"id": user.ID.Hex(), "name": user.Name, "email": user.Email, "role": user.Role})
	})

	app.Get("/api/users", func(c *fiber.Ctx) error {
		ctx := context.Background()
		cur, err := db.Collection("users").Find(ctx, bson.M{})
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		var users []models.User
		if err := cur.All(ctx, &users); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		// Only return id, name, email, role, avatar
		var result []fiber.Map
		for _, u := range users {
			result = append(result, fiber.Map{
				"id":     u.ID.Hex(),
				"name":   u.Name,
				"email":  u.Email,
				"role":   u.Role,
				"avatar": u.Avatar,
			})
		}
		return c.JSON(result)
	})
}
