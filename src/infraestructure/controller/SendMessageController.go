package controller

import (
	"api/src/application"
	"api/src/domain"
	"net/http"

	"github.com/gin-gonic/gin"
)

type SendController struct {
	message application.CaseUseMsj
}

func NewSendController(message application.CaseUseMsj) *SendController {
	return &SendController{message: message}
}

func (cp *SendController) Execute(c *gin.Context) {
	var message domain.Message

	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := cp.message.Execute(message.Header, message.Describtion, message.Image)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": err.Error()})
	}
	c.JSON(http.StatusCreated, gin.H{"message": "Mensaje enviado a la cola"})
}
