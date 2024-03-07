// auth.go
package routes

import (
    "genesis/controllers"
    "genesis/middleware"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/contrib/websocket"
)

// SetupAuthRoutes sets up authentication routes
func SetupAuthRoutes(router fiber.Router) {
    // router.Post("/register", controllers.SignUpUser)
    router.Post("/login", controllers.SignInUser)
    router.Post("/loginemail", controllers.EmailCheck)
    router.Get("/logout", middleware.DeserializeUser, controllers.LogoutUser)
    router.Get("/verifyemail/:verificationCode", controllers.VerifyEmail)
    router.Get("/ws/:email", websocket.New(func(c *websocket.Conn) {
        // Handle WebSocket connection
        controllers.HandleWebSocket(c)
    }))
    router.Post("/forgotpassword", controllers.ForgotPassword)
    router.Patch("/resetpassword/:resetToken", controllers.ResetPassword)
    router.Post("/upload", middleware.DeserializeUser, controllers.UploadFile)

    // router.Get("/ClickStatus/:Email", controllers.CheckVerificationBool)
    // router.
    // router.Get("/sessions/oauth/google", controllers.GoogleOAuth)
    // router.Get("/sessions/oauth/github", controllers.GitHubOAuth)
}
