package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"github.com/streadway/amqp"
	"golang.org/x/oauth2/google"
)

// Archivo multi-5a.json consultar con cato.
var db *sql.DB
var rabbitMQURL = os.Getenv("RABBIT")
var queueName = os.Getenv("QUEUENAME")

type RabbitMessage struct {
	Header      string `json:"header"`
	Description string `json:"description"`
	Image       string `json:"image"`
	Status      string `json:"status"`
}

func initDB() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error cargando el archivo .env")
	}
	dbHost := os.Getenv("DB_HOST")
	dbUser := os.Getenv("DB_USER")
	dbPass := os.Getenv("DB_PASS")
	dbSchema := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", dbUser, dbPass, dbHost, dbSchema)
	db, err = sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Error conectando a la BD: %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("No se pudo conectar a MySQL: %v", err)
	}
	fmt.Println("Conectado a MySQL")
}

type SubscriptionRequest struct {
	Token string `json:"token"`
	Topic string `json:"topic"`
}

type FCMNotification struct {
	To   string `json:"to"`
	Data struct {
		Message string `json:"message"`
	} `json:"data"`
}

// Función para obtener el token de acceso de Firebase
func getAccessToken() (string, error) {
	data, err := ioutil.ReadFile("./multi-5a.json")
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

// Guardar el token en la base de datos
func saveTokenToDB(token string) (int64, error) {
	query := "INSERT INTO user (token) VALUES (?)"
	result, err := db.Exec(query, token)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// Enviar notificación FCM usando la API v1
func sendNotification(token string) error {
	accessToken, err := getAccessToken()
	if err != nil {
		return fmt.Errorf("error obteniendo token de acceso: %v", err)
	}

	// Construcción del JSON de la notificación
	notif := map[string]interface{}{
		"message": map[string]interface{}{
			"token": token,
			"notification": map[string]string{
				"title": "Registro exitoso",
				"body":  "¡Tu token fue guardado exitosamente!",
			},
			"data": map[string]string{
				"status": "success",
			},
		},
	}

	jsonData, err := json.Marshal(notif)
	if err != nil {
		return fmt.Errorf("error generando JSON de la notificación: %v", err)
	}
	IDcliente := os.Getenv("ID_CLIENTE")
	if IDcliente == "" {
		fmt.Println("La variable de entorno 'ID_CLIENTE' no está configurada.")
		return err
	}

	// Nueva URL de Firebase API v1
	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", IDcliente)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creando solicitud HTTP: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error enviando notificación: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Respuesta FCM:", string(body))
	return nil
}

func subscribeHandler(w http.ResponseWriter, r *http.Request) {
	var req SubscriptionRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, `{"error": "Solicitud inválida"}`, http.StatusBadRequest)
		fmt.Println("Error decodificando solicitud:", err)
		return
	}

	if req.Token == "" {
		http.Error(w, `{"error": "Token requerido"}`, http.StatusBadRequest)
		fmt.Println("Error: Token vacío")
		return
	}

	// Guardar en BD
	id, err := saveTokenToDB(req.Token)
	if err != nil {
		http.Error(w, `{"error": "Error guardando en BD"}`, http.StatusInternalServerError)
		fmt.Println("Error guardando en BD:", err)
		return
	}

	err = sendNotification(req.Token)
	if err != nil {
		http.Error(w, `{"error": "Token guardado, pero error en notificación"}`, http.StatusInternalServerError)
		fmt.Println("Error enviando notificación:", err)
		return
	}

	// Responder en JSON
	response := map[string]interface{}{
		"success": true,
		"userId":  id,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Manejar preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func consumeRabbitMQ() {
	// Conectar a RabbitMQ
	conn, err := amqp.Dial(rabbitMQURL)
	if err != nil {
		log.Fatalf("Error conectando a RabbitMQ: %v", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("Error abriendo un canal: %v", err)
	}
	defer ch.Close()

	// Asegurar que la cola existe
	_, err = ch.QueueDeclare(
		queueName,
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		log.Fatalf("Error declarando la cola: %v", err)
	}

	// Consumir mensajes
	msgs, err := ch.Consume(
		queueName,
		"",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		log.Fatalf("Error al consumir mensajes: %v", err)
	}

	// Leer los mensajes de la cola
	go func() {
		for msg := range msgs {
			fmt.Println("Mensaje recibido de RabbitMQ:", string(msg.Body))

			// Decodificar el mensaje JSON
			var rabbitMsg RabbitMessage
			if err := json.Unmarshal(msg.Body, &rabbitMsg); err != nil {
				fmt.Println("Error decodificando mensaje:", err)
				continue
			}

			// Enviar la notificación
			err := sendRabbitNotification(rabbitMsg.Header, rabbitMsg.Description, rabbitMsg.Image)
			if err != nil {
				fmt.Println("Error enviando notificación:", err)
			}
		}
	}()
	fmt.Println("Escuchando mensajes de RabbitMQ...")
}

func sendRabbitNotification(header, description, image string) error {
	// Obtener todos los tokens de usuarios registrados
	rows, err := db.Query("SELECT token FROM user")
	if err != nil {
		return fmt.Errorf("error obteniendo tokens de usuarios: %v", err)
	}
	defer rows.Close()

	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return fmt.Errorf("error leyendo token de usuario: %v", err)
		}
		tokens = append(tokens, token)
	}

	// Enviar la notificación a cada usuario
	for _, token := range tokens {
		err := sendFCMNotification(token, header, description, image)
		if err != nil {
			fmt.Printf("Error enviando notificación a %s: %v\n", token, err)
		}
	}

	return nil
}

// Método para enviar notificaciones personalizadas desde RabbitMQ
func sendFCMNotification(token, header, description, image string) error {
	accessToken, err := getAccessToken()
	if err != nil {
		return fmt.Errorf("error obteniendo token de acceso: %v", err)
	}

	// Construcción del JSON de la notificación
	notif := map[string]interface{}{
		"message": map[string]interface{}{
			"token": token,
			"notification": map[string]string{
				"title": header,
				"body":  description,
			},
			"data": map[string]string{
				"image": image,
			},
		},
	}

	jsonData, err := json.Marshal(notif)
	if err != nil {
		return fmt.Errorf("error generando JSON de la notificación: %v", err)
	}

	IDcliente := os.Getenv("ID_CLIENTE")
	if IDcliente == "" {
		fmt.Println("La variable de entorno 'ID_CLIENTE' no está configurada.")
		return err
	}

	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", IDcliente)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("error creando solicitud HTTP: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error enviando notificación: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Respuesta de FCM:", string(body))
	return nil
}

func main() {
	initDB()
	go consumeRabbitMQ()

	mux := http.NewServeMux()
	mux.HandleFunc("/suscribe-topic", subscribeHandler)

	// Usar middleware CORS
	handler := corsMiddleware(mux)

	log.Println("Servidor escuchando en el puerto 8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}
