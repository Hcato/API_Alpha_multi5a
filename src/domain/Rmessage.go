package domain

type SendMessage interface {
	Send(message Message) error
}
