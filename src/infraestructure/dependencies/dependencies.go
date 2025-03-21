package dependencies

import (
	"api/src/application"
	"api/src/infraestructure"
	"api/src/infraestructure/controller"
	"fmt"
)

var rabbitMQProducer *infraestructure.RabbitMQProducer

func Init() {
	var err error
	rabbitMQProducer, err = infraestructure.NewRabbitMQProducer("amqp://cato:5678@3.233.111.240/", "messages")
	if err != nil {
		fmt.Println("Error al conectar con RabbitMQ:", err)
		return
	}
}
func CloseRabbitMQ() {
	if rabbitMQProducer != nil {
		rabbitMQProducer.Close()
		fmt.Println("Conexión a RabbitMQ cerrada.")
	}
}

func GetController() *controller.SendController {
	usecase := application.SendMessage(rabbitMQProducer)
	return controller.NewSendController(*usecase)
}
