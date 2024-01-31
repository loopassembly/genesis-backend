// user.go
package routes

import (
	"github.com/gofiber/fiber/v2"
	"genesis/controllers"
	"genesis/middleware"
)

func SetupUserRoutes(router fiber.Router) {
	router.Get("/me", middleware.DeserializeUser, controllers.GetMe)
}