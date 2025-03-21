package domain

type Message struct {
	Header      string  `json:"header"`
	Describtion string  `json:"description"`
	Image       *string `json:"image,omitempty"`
	Status      string  `json:"status"`
}

func NewMessage(header string, description string, imagen *string) *Message {
	return &Message{Header: header, Describtion: description, Image: imagen, Status: ""}
}
