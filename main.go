package main

import (
	message "api/src/infraestructure/dependencies"
	messageRoute "api/src/infraestructure/routes"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	message.Init()
	defer message.CloseRabbitMQ()

	r := gin.Default()
	r.Use(func(c *gin.Context) {
		log.Printf("Solicitud recibida: %s %s", c.Request.Method, c.Request.URL.Path)
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	})
	messageRoute.Routes(r)
	r.Use()
	r.Run()
}
