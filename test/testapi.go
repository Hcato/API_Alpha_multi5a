package main

import (
	"context"
	_ "encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"golang.org/x/oauth2/google"
)

// Testeo de credenciales
func getAccessToken() (string, error) {
	data, err := ioutil.ReadFile("../consumer/multi-5a.json") // Ruta a tu archivo JSON de credenciales
	if err != nil {
		return "", fmt.Errorf("error leyendo archivo de cuenta de servicio: %v", err)
	}

	config, err := google.JWTConfigFromJSON(data, "https://www.googleapis.com/auth/firebase.messaging")
	if err != nil {
		return "", fmt.Errorf("error creando configuración JWT: %v", err)
	}

	token, err := config.TokenSource(context.Background()).Token()
	if err != nil {
		return "", fmt.Errorf("error obteniendo token de acceso: %v", err)
	}

	return token.AccessToken, nil
}

func main() {
	token, err := getAccessToken()
	if err != nil {
		log.Fatalf("Error obteniendo token de acceso: %v", err)
	}

	fmt.Println("🔑 Token de acceso obtenido:")
	fmt.Println(token)
}
