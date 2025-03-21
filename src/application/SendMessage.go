package application

import "api/src/domain"

type CaseUseMsj struct {
	SendMessage domain.SendMessage
}

func SendMessage(message domain.SendMessage) *CaseUseMsj {
	return &CaseUseMsj{SendMessage: message}
}

func (cp *CaseUseMsj) Execute(header string, description string, imagen *string) error {
	message := domain.NewMessage(header, description, imagen)
	message.Status = "enviado"
	return cp.SendMessage.Send(*message)
}
