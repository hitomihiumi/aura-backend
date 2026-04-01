package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// --- Models ---

type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	DiscordID string    `gorm:"uniqueIndex" json:"discord_id"`
	Username  string    `json:"username"`
	AvatarURL string    `json:"avatar_url"`
	CreatedAt time.Time `json:"created_at"`
}

type Chat struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `json:"user_id"`
	Title     string    `json:"title"`
	CreatedAt time.Time `json:"created_at"`
}

type Message struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	ChatID     uint      `json:"chat_id"`
	Role       string    `json:"role"`
	Content    string    `json:"content"`
	Images     string    `json:"images"` // JSON array of base64 strings
	TokensUsed int       `json:"tokens_used"`
	CreatedAt  time.Time `json:"created_at"`
}

// --- Globals ---
var DB *gorm.DB
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
var discordOAuthConfig *oauth2.Config
var ollamaURL = os.Getenv("OLLAMA_URL")
var maxContextTokens = 8192

func init() {
	if ollamaURL == "" {
		ollamaURL = "http://ollama:11434/api/chat"
	}
}

// --- Init DB ---
func initDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "host=localhost user=postgres password=postgres dbname=postgres port=5432 sslmode=disable"
	}

	var err error
	// Retry loop for database connection
	for i := 1; i <= 10; i++ {
		DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
		if err == nil {
			log.Println("Successfully connected to the database!")
			break
		}
		log.Printf("Attempt %d/10: Failed to connect to database, retrying in 3 seconds... (%v)", i, err)
		time.Sleep(3 * time.Second)
	}

	if err != nil {
		log.Fatalf("Failed to connect to database after retries: %v", err)
	}

	err = DB.AutoMigrate(&User{}, &Chat{}, &Message{})
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}
}

// --- OAuth ---
func initOAuth() {
	discordOAuthConfig = &oauth2.Config{
		RedirectURL:  os.Getenv("DISCORD_REDIRECT_URL"),
		ClientID:     os.Getenv("DISCORD_CLIENT_ID"),
		ClientSecret: os.Getenv("DISCORD_CLIENT_SECRET"),
		Scopes:       []string{"identify", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/oauth2/token",
		},
	}
}

// --- Handlers ---
func discordLogin(c *fiber.Ctx) error {
	url := discordOAuthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	return c.Redirect(url)
}

func discordCallback(c *fiber.Ctx) error {
	code := c.Query("code")
	token, err := discordOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Failed to exchange token"})
	}

	client := discordOAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://discord.com/api/users/@me")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to get user info"})
	}
	defer resp.Body.Close()

	var discordUser struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Avatar   string `json:"avatar"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&discordUser); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to decode user info"})
	}

	avatarURL := fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", discordUser.ID, discordUser.Avatar)

	var user User
	if DB.Where("discord_id = ?", discordUser.ID).First(&user).Error != nil {
		user = User{
			DiscordID: discordUser.ID,
			Username:  discordUser.Username,
			AvatarURL: avatarURL,
		}
		DB.Create(&user)
	} else {
		user.Username = discordUser.Username
		user.AvatarURL = avatarURL
		DB.Save(&user)
	}

	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})

	t, err := jwtToken.SignedString(jwtSecret)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate token"})
	}

	return c.JSON(fiber.Map{
		"token": t,
		"user":  user,
	})
}

// Auth Middleware
func authMiddleware(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" || len(authHeader) < 8 {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Missing or invalid token"})
	}
	tokenString := authHeader[7:]

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid claims"})
	}

	c.Locals("user_id", uint(claims["user_id"].(float64)))
	return c.Next()
}

func createChat(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	type Request struct {
		Title string `json:"title"`
	}
	var req Request
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	chat := Chat{
		UserID: userID,
		Title:  req.Title,
	}
	DB.Create(&chat)
	return c.JSON(chat)
}

func getChats(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)
	var chats []Chat
	DB.Where("user_id = ?", userID).Find(&chats)
	return c.JSON(chats)
}

func getChatHistory(c *fiber.Ctx) error {
	chatID := c.Params("id")
	var messages []Message
	DB.Where("chat_id = ?", chatID).Order("created_at asc").Find(&messages)
	return c.JSON(messages)
}

func uploadFile(c *fiber.Ctx) error {
	file, err := c.FormFile("file")
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "No file uploaded"})
	}

	f, err := file.Open()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to open file"})
	}
	defer f.Close()

	fileBytes, err := io.ReadAll(f)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read file"})
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".webp" { // Image for vision model
		base64Str := base64.StdEncoding.EncodeToString(fileBytes)
		return c.JSON(fiber.Map{
			"type":    "image",
			"content": base64Str,
		})
	}

	// Treat as text
	return c.JSON(fiber.Map{
		"type":    "text",
		"content": string(fileBytes),
	})
}

func fetchGithub(c *fiber.Ctx) error {
	type GithubReq struct {
		URL string `json:"url"` // expecting something like https://github.com/user/repo/blob/main/file.go or raw url
	}
	var req GithubReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	rawURL := req.URL
	if strings.Contains(rawURL, "github.com") && strings.Contains(rawURL, "/blob/") {
		rawURL = strings.Replace(rawURL, "github.com", "raw.githubusercontent.com", 1)
		rawURL = strings.Replace(rawURL, "/blob/", "/", 1)
	}

	resp, err := http.Get(rawURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Failed to fetch from GitHub"})
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to read response"})
	}

	return c.JSON(fiber.Map{
		"type":    "text",
		"content": string(bodyBytes),
	})
}

type OllamaMessage struct {
	Role    string   `json:"role"`
	Content string   `json:"content"`
	Images  []string `json:"images,omitempty"`
}

type OllamaRequest struct {
	Model    string          `json:"model"`
	Messages []OllamaMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type OllamaResponse struct {
	Model           string        `json:"model"`
	Message         OllamaMessage `json:"message"`
	Done            bool          `json:"done"`
	PromptEvalCount int           `json:"prompt_eval_count"`
	EvalCount       int           `json:"eval_count"`
}

func sendMessageStream(c *fiber.Ctx) error {
	chatIDStr := c.Params("id")
	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid chat ID"})
	}
	userID := c.Locals("user_id").(uint)

	// Verify chat belongs to user
	var chat Chat
	if err := DB.First(&chat, "id = ? AND user_id = ?", chatID, userID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "Chat not found"})
	}

	type Request struct {
		Content string   `json:"content"`
		Images  []string `json:"images"`
	}
	var req Request
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	imagesJSON, _ := json.Marshal(req.Images)

	// Save user message
	userMsg := Message{
		ChatID:    uint(chatID),
		Role:      "user",
		Content:   req.Content,
		Images:    string(imagesJSON),
		CreatedAt: time.Now(),
	}
	DB.Create(&userMsg)

	// Fetch context (e.g. last 20 messages)
	var history []Message
	DB.Where("chat_id = ?", chatID).Order("created_at desc").Limit(20).Find(&history)

	// Build ollama request messages (reverse to chronological)
	var ollamaMessages []OllamaMessage
	for i := len(history) - 1; i >= 0; i-- {
		var imgs []string
		if history[i].Images != "" && history[i].Images != "null" {
			json.Unmarshal([]byte(history[i].Images), &imgs)
		}
		ollamaMessages = append(ollamaMessages, OllamaMessage{
			Role:    history[i].Role,
			Content: history[i].Content,
			Images:  imgs,
		})
	}
	// Add current message if history didn't fetch it synchronously
	if len(ollamaMessages) == 0 || ollamaMessages[len(ollamaMessages)-1].Content != req.Content {
		ollamaMessages = append(ollamaMessages, OllamaMessage{
			Role:    "user",
			Content: req.Content,
			Images:  req.Images,
		})
	}

	ollamaReq := OllamaRequest{
		Model:    "gemma", // Configure model as needed
		Messages: ollamaMessages,
		Stream:   true,
	}
	reqBytes, _ := json.Marshal(ollamaReq)

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")

	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		httpMsg, err := http.Post(ollamaURL, "application/json", bytes.NewBuffer(reqBytes))
		if err != nil {
			fmt.Fprintf(w, "data: {\"error\": \"Failed to connect to LLM\"}\n\n")
			w.Flush()
			return
		}
		defer httpMsg.Body.Close()

		scanner := bufio.NewScanner(httpMsg.Body)
		var fullAssistantContent string
		var promptTokens, evalTokens int

		for scanner.Scan() {
			var resp OllamaResponse
			if err := json.Unmarshal(scanner.Bytes(), &resp); err == nil {
				if resp.Message.Content != "" {
					fullAssistantContent += resp.Message.Content
					// Send chunk
					chunkData, _ := json.Marshal(map[string]interface{}{
						"content": resp.Message.Content,
					})
					fmt.Fprintf(w, "data: %s\n\n", chunkData)
					w.Flush()
				}
				if resp.Done {
					promptTokens = resp.PromptEvalCount
					evalTokens = resp.EvalCount
				}
			}
		}

		totalTokens := promptTokens + evalTokens
		contextPercent := float64(totalTokens) / float64(maxContextTokens) * 100

		// Save assistant message
		assistantMsg := Message{
			ChatID:     uint(chatID),
			Role:       "assistant",
			Content:    fullAssistantContent,
			Images:     "[]",
			TokensUsed: totalTokens,
			CreatedAt:  time.Now(),
		}
		DB.Create(&assistantMsg)

		// Send final metadata
		metaData, _ := json.Marshal(map[string]interface{}{
			"done":               true,
			"prompt_tokens":      promptTokens,
			"completion_tokens":  evalTokens,
			"total_tokens":       totalTokens,
			"context_percentage": contextPercent,
		})
		fmt.Fprintf(w, "data: %s\n\n", metaData)
		w.Flush()
	})

	return nil
}

func main() {
	_ = godotenv.Load()
	if len(jwtSecret) == 0 {
		jwtSecret = []byte("supersecret")
	}

	initDB()
	initOAuth()

	app := fiber.New()

	// Auth routes
	authGroup := app.Group("/auth/discord")
	authGroup.Get("/login", discordLogin)
	authGroup.Get("/callback", discordCallback)

	// API routes
	apiGroup := app.Group("/api", authMiddleware)
	apiGroup.Post("/chats", createChat)
	apiGroup.Get("/chats", getChats)
	apiGroup.Get("/chats/:id/messages", getChatHistory)
	apiGroup.Post("/chats/:id/messages", sendMessageStream)
	apiGroup.Post("/upload", uploadFile)
	apiGroup.Post("/github/fetch", fetchGithub)

	log.Println("Server successfully started on port 3000")
	log.Fatal(app.Listen(":3000"))
}
