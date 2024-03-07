package controllers

import (
	"fmt"
	"genesis/initializers"
	"genesis/models"
	"genesis/utils"
	// "io"
	"log"
	"net/http"
	// "os"
	"path/filepath"
	"strings"

	// "github.com/gofiber/websocket/v2"
	"github.com/gofiber/contrib/websocket"
	"github.com/google/uuid"

	// "sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"github.com/thanhpk/randstr"
	"golang.org/x/crypto/bcrypt"
)

func VerifyEmail(c *fiber.Ctx) error {
    code := c.Params("verificationCode")
    var existingUser models.User
    result := initializers.DB.First(&existingUser, "verification_code = ?", code)
    if result.Error != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Invalid verification code"})
    }

    // User exists and signup details are complete

    // Set the Clicked field to true
    existingUser.Clicked = true

    // Clear the verification code
    existingUser.VerificationCode = ""

    // Set the Verified field to true
	verify:=true
    existingUser.Verified = &verify

    // Update the user record in the database
    if err := initializers.DB.Save(&existingUser).Error; err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Failed to update user"})
    }

    // Generate JWT token and log the user in
    user := models.User{
        ID: existingUser.ID,
    }
    config, _ := initializers.LoadConfig(".")
    tokenByte := jwt.New(jwt.SigningMethodHS256)

    now := time.Now().UTC()
    claims := tokenByte.Claims.(jwt.MapClaims)

    claims["sub"] = user.ID
    claims["exp"] = now.Add(config.JwtExpiresIn).Unix()
    claims["iat"] = now.Unix()
    claims["nbf"] = now.Unix()

    tokenString, err := tokenByte.SignedString([]byte(config.JwtSecret))

    if err != nil {
        return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"status": "fail", "message": fmt.Sprintf("generating JWT Token failed: %v", err)})
    }

    c.Cookie(&fiber.Cookie{
        Name:     "token",
        Value:    tokenString,
        Path:     "/",
        MaxAge:   config.JwtMaxAge * 60,
        Secure:   false,
        HTTPOnly: true,
        Domain:   "localhost",
    })

    return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": "CLICKED", "token": tokenString})
}



func HandleWebSocket(c *websocket.Conn) {
    // Retrieve email from the websocket connection parameters
    email := c.Params("email")

    // Goroutine to continuously check if the user's Clicked field changes
    go func() {
        for {
            // Retrieve the user with the specified email from the database
            var existingUser models.User
            result := initializers.DB.First(&existingUser, "email = ?", email)
            if result.Error != nil {
                log.Println("Error retrieving user:", result.Error)
                return
            }

            // Check if the user's Clicked field is true
            if existingUser.Clicked {
                // Check if the Name and Dob fields are not empty
                if existingUser.Name != "" && existingUser.Dob != "" {
                    // Send a message to the client indicating that the user has clicked
                    message := []byte("User clicked")
                    if err := c.WriteMessage(websocket.TextMessage, message); err != nil {
                        log.Println("Error sending message:", err)
                    }
                } else {
                    // Send a different message if either Name or Dob field is empty
                    message := []byte("User details incomplete")
                    if err := c.WriteMessage(websocket.TextMessage, message); err != nil {
                        log.Println("Error sending message:", err)
                    }
                }

                // Update the user's Clicked field to false
                existingUser.Clicked = false
                if err := initializers.DB.Save(&existingUser).Error; err != nil {
                    log.Println("Error updating user:", err)
                }
            }

            time.Sleep(2 * time.Second) // Check every 2 seconds
        }
    }()

    // Goroutine to periodically send a "Hello" message to the client
    // go func() {
    //     ticker := time.NewTicker(2 * time.Second)
    //     defer ticker.Stop()

    //     for {
    //         select {
    //         case <-ticker.C:
    //             // Send a response back to the client
    //             response := []byte("Hello")
    //             if err := c.WriteMessage(websocket.TextMessage, response); err != nil {
    //                 log.Println("write:", err)
    //                 return
    //             }
    //         }
    //     }
    // }()

    // Handle incoming messages from the client
    for {
        _, _, err := c.ReadMessage()
        if err != nil {
            log.Println("read:", err)
            break
        }
    }
}



func ForgotPassword(c *fiber.Ctx) error {
	var payload *models.ForgotPasswordInput

	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": err.Error()})
	}

	message := "You will receive a reset email if the user with that email exists"

	var user models.User
	result := initializers.DB.First(&user, "email = ?", strings.ToLower(payload.Email))
	if result.Error != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Invalid email or Password"})
	}

	if !*user.Verified {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"status": "error", "message": "Account not verified"})
	}

	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Fatal("Could not load config", err)
	}

	// Generate Verification Code
	resetToken := randstr.String(20)

	passwordResetToken := utils.Encode(resetToken)
	user.PasswordResetToken = passwordResetToken
	user.PasswordResetAt = time.Now().Add(time.Minute * 15)
	initializers.DB.Save(&user)

	firstName := user.Name
	if strings.Contains(firstName, " ") {
		firstName = strings.Split(firstName, " ")[1]
	}

	// Send Email
	emailData := utils.EmailData{
		URL:       config.ClientOrigin + "api/auth/resetpassword/" + resetToken,
		FirstName: firstName,
		Subject:   "Your password reset token (valid for 10min)",
	}

	utils.SendEmail(&user, &emailData, "resetPassword.html")

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": message})
}

func ResetPassword(c *fiber.Ctx) error {
	var payload *models.ResetPasswordInput
	resetToken := c.Params("resetToken")

	if err := c.BodyParser(&payload); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": err.Error()})
	}

	if payload.Password != payload.PasswordConfirm {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Passwords do not match"})
	}

	hashedPassword, _ := utils.HashPassword(payload.Password)

	passwordResetToken := utils.Encode(resetToken)

	var updatedUser models.User
	result := initializers.DB.First(&updatedUser, "password_reset_token = ? AND password_reset_at > ?", passwordResetToken, time.Now())
	if result.Error != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "The reset token is invalid or has expired"})
	}

	updatedUser.Password = hashedPassword
	updatedUser.PasswordResetToken = ""
	initializers.DB.Save(&updatedUser)

	// Assuming you want to clear a token in the response
	c.ClearCookie("token")

	return c.Status(http.StatusOK).JSON(fiber.Map{"status": "success", "message": "Password data updated successfully"})
}

func renderConfirmationTemplate(c *fiber.Ctx) error {

	// Render the template and send the output to the client
	return c.Render("index", fiber.Map{
		"Title": "Hello, World!",
	})

}

func SignInUser(c *fiber.Ctx) error {
	var payload *models.SignInInput

	if err := c.BodyParser(&payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": err.Error()})
	}

	errors := models.ValidateStruct(payload)
	if errors != nil {
		return c.Status(fiber.StatusBadRequest).JSON(errors)

	}

	var user models.User
	result := initializers.DB.First(&user, "email = ?", strings.ToLower(payload.Email))
	if result.Error != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Invalid email or Password"})
	}
	if !*user.Verified {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Email not verified"})
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(payload.Password))
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Invalid email or Password"})
	}

	config, _ := initializers.LoadConfig(".")

	tokenByte := jwt.New(jwt.SigningMethodHS256)

	now := time.Now().UTC()
	claims := tokenByte.Claims.(jwt.MapClaims)

	claims["sub"] = user.ID
	claims["exp"] = now.Add(config.JwtExpiresIn).Unix()
	claims["iat"] = now.Unix()
	claims["nbf"] = now.Unix()

	tokenString, err := tokenByte.SignedString([]byte(config.JwtSecret))

	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"status": "fail", "message": fmt.Sprintf("generating JWT Token failed: %v", err)})
	}

	c.Cookie(&fiber.Cookie{
		Name:     "token",
		Value:    tokenString,
		Path:     "/",
		MaxAge:   config.JwtMaxAge * 60,
		Secure:   false,
		HTTPOnly: true,
		Domain:   "localhost",
	})

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "token": tokenString})
}

func EmailCheck(c *fiber.Ctx) error {
	var payload *models.SignInInput

	if err := c.BodyParser(&payload); err != nil {
		log.Print(err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"status": "fail", "message": "Invalid request payload"})
	}

	// Assuming email is the only required field for authentication
	email := strings.ToLower(payload.Email)

	var existingUser models.User
	result := initializers.DB.First(&existingUser, "email = ?", email)
	if result.RowsAffected > 0 {
		// User already exists, update verification code and resend email
		config, err := initializers.LoadConfig(".")
		if err != nil {
			log.Print(err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Internal Server Error"})
		}

		code := randstr.String(20)
		verificationCode := utils.Encode(code)
		existingUser.Verified = new(bool)
		*existingUser.Verified = false
		existingUser.VerificationCode = verificationCode
		if err := initializers.DB.Save(&existingUser).Error; err != nil {
			log.Print(err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Internal Server Error"})
		}

		emailData := utils.EmailData{
			URL:     config.ClientOrigin + "api/auth/verifyemail/" + verificationCode,
			Subject: "Your account verification code",
		}
		utils.SendEmail(&existingUser, &emailData, "verificationCode.html")

		message := "We sent an email with a new verification code to " + existingUser.Email

		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": message})
	}

	// User doesn't exist, create a new user and send verification email
	newUser := models.User{
		Email: strings.ToLower(email),
	}

	config, err := initializers.LoadConfig(".")
	if err != nil {
		log.Print(err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Internal Server Error"})
	}

	code := randstr.String(20)
	verificationCode := utils.Encode(code)
	newUser.VerificationCode = verificationCode
	if err := initializers.DB.Save(&newUser).Error; err != nil {
		log.Print(err)
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"status": "error", "message": "Internal Server Error"})
	}

	emailData := utils.EmailData{
		URL:     config.ClientOrigin + "api/auth/verifyemail/" + verificationCode,
		Subject: "Your account verification code",
	}
	utils.SendEmail(&newUser, &emailData, "verificationCode.html")

	message := "We sent an email with a verification code to " + newUser.Email

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success", "message": message})
}

func LogoutUser(c *fiber.Ctx) error {
	expired := time.Now().Add(-time.Hour * 24)
	c.Cookie(&fiber.Cookie{
		Name:    "token",
		Value:   "",
		Expires: expired,
	})
	return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "success"})
}



func UploadFile(c *fiber.Ctx) error {
	// Parse the form data
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Failed to parse form data"})
	}

	// Access the user information from the request context
	user := c.Locals("user").(models.UserResponse)

	// Access the files from the form data
	files := form.File["files"]

	// Process each file
	for _, file := range files {
		// Open the uploaded file
		src, err := file.Open()
		if err != nil {
			return err
		}
		defer src.Close()

		// Generate a unique file name
		fileName := GenerateFileName(file.Filename)

		// Construct the file path
		filePath := filepath.Join("uploads", user.ID.String(), fileName)

		// Create the file record in the database
		fileRecord := models.Document{
			UserID:   user.ID.String(),
			FileName: fileName,
			FilePath: filePath,
			FileType: GetFileType(file.Filename),
		}

		// Save the file record to the database
		if err := models.DB.Create(&fileRecord).Error; err != nil {
			return err
		}

		// Save the file to the specified path
		if err := c.SaveFile(file, filePath); err != nil {
			return err
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"message": "Files uploaded successfully"})
}

// GenerateFileName generates a unique file name for uploaded files
func GenerateFileName(originalName string) string {
	// Generate a unique file name based on the original file name
	fileExt := filepath.Ext(originalName)
	fileName := strings.TrimSuffix(originalName, fileExt)
	uniqueID := uuid.New().String()
	return fmt.Sprintf("%s_%s%s", fileName, uniqueID, fileExt)
}

// GetFileType returns the type of the file based on its extension
func GetFileType(fileName string) string {
	extension := filepath.Ext(fileName)
	switch strings.ToLower(extension) {
	case ".jpg", ".jpeg", ".png", ".gif":
		return "image"
	case ".pdf":
		return "pdf"
	case ".doc", ".docx":
		return "document"
	default:
		return "other"
	}
}
