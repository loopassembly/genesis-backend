// auth.go
package routes

import (
	"genesis/controllers"
	"genesis/middleware"

	"github.com/gofiber/fiber/v2"
)

// all auth routes including oauth
func SetupAuthRoutes(router fiber.Router) {
	router.Post("/register", controllers.SignUpUser)
	router.Post("/login", controllers.SignInUser)
	router.Post("/loginemail",controllers.EmailCheck)
	router.Get("/logout", middleware.DeserializeUser, controllers.LogoutUser)
	router.Get("/verifyemail/:verificationCode", controllers.VerifyEmail)
	router.Post("/forgotpassword", controllers.ForgotPassword)
	router.Patch("/resetpassword/:resetToken", controllers.ResetPassword)
	router.Get("/ClickStatus/:Email", controllers.CheckVerificationBool)
	// router.
	// router.Get("/sessions/oauth/google", controllers.GoogleOAuth)
	// router.Get("/sessions/oauth/github", controllers.GitHubOAuth)
}
