package routes

import (
	"api/src/infraestructure/dependencies"

	"github.com/gin-gonic/gin"
)

func Routes(router *gin.Engine) {
	routes := router.Group("/message")
	sendmessage := dependencies.GetController().Execute

	routes.POST("/", sendmessage)
}
