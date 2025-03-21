package infraestructure

import (
	"api/src/domain"
	"context"
	"encoding/json"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

type RabbitMQProducer struct {
	conn    *amqp.Connection
	channel *amqp.Channel
	queue   string
}

func NewRabbitMQProducer(uri, queueName string) (*RabbitMQProducer, error) {
	conn, err := amqp.Dial(uri)
	if err != nil {
		return nil, err
	}

	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}

	_, err = ch.QueueDeclare(
		queueName, true, false, false, false, nil,
	)
	if err != nil {
		return nil, err
	}

	return &RabbitMQProducer{conn: conn, channel: ch, queue: queueName}, nil
}

func (r *RabbitMQProducer) Send(message domain.Message) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	body, err := json.Marshal(message)
	if err != nil {
		return err
	}

	err = r.channel.PublishWithContext(ctx,
		"", r.queue, false, false,
		amqp.Publishing{
			ContentType: "application/json",
			Body:        body,
		},
	)
	if err != nil {
		return err
	}

	log.Printf(" [x] Sent %s\n", body)
	return nil
}

func (r *RabbitMQProducer) Close() {
	r.channel.Close()
	r.conn.Close()
}
