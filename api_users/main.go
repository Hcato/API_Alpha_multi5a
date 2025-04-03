package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

type CollaboratorsWithStation struct {
	Collaborators []CollaboratorWithUser `json:"collaborators"`
	Station       Station                `json:"station"`
}

type StationWithCollaborators struct {
	ID            int                    `json:"id"`
	Name          string                 `json:"name"`
	Latitude      string                 `json:"latitude"`
	Longitude     string                 `json:"longitude"`
	OwnerID       int                    `json:"owner_id"`
	Plan          string                 `json:"plan"`
	Collaborators []CollaboratorWithUser `json:"collaborators"`
}

type RequestWithUser struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	StationID int    `json:"station_id"`
	Status    string `json:"status"`
	User      User   `json:"user"`
}

type Request struct {
	ID        int    `json:"id"`
	UserID    int    `json:"user_id"`
	StationID int    `json:"station_id"`
	Status    string `json:"status"`
}

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
	Image    string `json:"image,omitempty"`
	Token    string `json:"token,omitempty"`
	Token2   string `json:"token2,omitempty"`
}

type Station struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	Latitude  string `json:"latitude"`
	Longitude string `json:"longitude"`
	OwnerID   int    `json:"owner_id"`
	Plan      string `json:"plan"`
}

type Collaborator struct {
	ID        int `json:"id"`
	UserID    int `json:"user_id"`
	StationID int `json:"station_id"`
}
type CollaboratorWithUser struct {
	Collaborator
	Username string `json:"username"`
	Image    string `json:"image"`
}

type StationWithOwner struct {
	ID        int     `json:"id"`
	Name      string  `json:"name"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	OwnerID   int     `json:"owner_id"`
	Plan      string  `json:"plan"`
	Owner     struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Image    string `json:"image"`
		Token    string `json:"token"`
		Token2   string `json:"token2"`
	} `json:"owner"`
}

var db *sql.DB

func initDB() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/%s",
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_NAME"))

	var errDB error
	db, errDB = sql.Open("mysql", dsn)
	if errDB != nil {
		log.Fatal(errDB)
	}
	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}
}

func getStationsWithCollaborators(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	userID := parseID(params["user_id"])

	// Primero obtenemos todas las estaciones del usuario
	stations, err := getStationsByUser(userID)
	if err != nil {
		http.Error(w, "Error fetching stations", http.StatusInternalServerError)
		return
	}

	// Para cada estación, obtenemos sus colaboradores
	var result []StationWithCollaborators
	for _, station := range stations {
		collaborators, err := getCollaboratorsForStation(station.ID)
		if err != nil {
			http.Error(w, "Error fetching collaborators", http.StatusInternalServerError)
			return
		}

		stationWithCollabs := StationWithCollaborators{
			ID:            station.ID,
			Name:          station.Name,
			Latitude:      station.Latitude,
			Longitude:     station.Longitude,
			OwnerID:       station.OwnerID,
			Plan:          station.Plan,
			Collaborators: collaborators,
		}
		result = append(result, stationWithCollabs)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// Función auxiliar para obtener estaciones de un usuario
func getStationsByUser(userID int) ([]Station, error) {
	rows, err := db.Query("SELECT id, name, latitude, longitude, owner_id, plan FROM stations WHERE owner_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var stations []Station
	for rows.Next() {
		var station Station
		if err := rows.Scan(&station.ID, &station.Name, &station.Latitude, &station.Longitude, &station.OwnerID, &station.Plan); err != nil {
			return nil, err
		}
		stations = append(stations, station)
	}
	return stations, nil
}

// Función auxiliar para obtener colaboradores de una estación
func getCollaboratorsForStation(stationID int) ([]CollaboratorWithUser, error) {
	rows, err := db.Query(`
        SELECT c.id, c.user_id, c.station_id, u.username, u.image 
        FROM collaborators c 
        JOIN users u ON c.user_id = u.id 
        WHERE c.station_id = ?`, stationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var collaborators []CollaboratorWithUser
	for rows.Next() {
		var collaborator CollaboratorWithUser
		if err := rows.Scan(&collaborator.ID, &collaborator.UserID, &collaborator.StationID, &collaborator.Username, &collaborator.Image); err != nil {
			return nil, err
		}
		collaborators = append(collaborators, collaborator)
	}
	return collaborators, nil
}

//-----------------------
//manejo de peticiones para ser colaborador

func createRequest(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var req Request
	json.NewDecoder(r.Body).Decode(&req)
	req.StationID = parseID(params["station_id"])

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// 1. Insertar la solicitud
	result, err := tx.Exec("INSERT INTO requests (user_id, station_id, status) VALUES (?, ?, 'pending')",
		req.UserID, req.StationID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	requestID, _ := result.LastInsertId()

	// 2. Obtener información del dueño y solicitante
	var ownerInfo struct {
		ID       int
		Username string
	}
	var requesterUsername string

	err = tx.QueryRow(`
        SELECT u.id, u.username 
        FROM stations s
        JOIN users u ON s.owner_id = u.id
        WHERE s.id = ?`, req.StationID).Scan(&ownerInfo.ID, &ownerInfo.Username)
	if err != nil {
		http.Error(w, "Error obteniendo info del dueño", http.StatusInternalServerError)
		return
	}

	err = tx.QueryRow("SELECT username FROM users WHERE id = ?", req.UserID).Scan(&requesterUsername)
	if err != nil {
		requesterUsername = "Un usuario"
	}

	tx.Commit()

	// 3. Enviar notificación a través de la API de mensajería
	go sendNotificationToMessagingAPI(ownerInfo.ID, requestID, req.StationID, requesterUsername)

	w.WriteHeader(http.StatusCreated)
}

func sendNotificationToMessagingAPI(ownerID int, requestID int64, stationID int, requesterUsername string) {
	// Obtener el token FCM del dueño (token2) directamente
	var ownerToken string
	err := db.QueryRow("SELECT token2 FROM users WHERE id = ?", ownerID).Scan(&ownerToken)
	if err != nil || ownerToken == "" {
		log.Printf("No se pudo obtener token FCM del dueño %d: %v", ownerID, err)
		return
	}

	notification := map[string]interface{}{
		"fcm_token": ownerToken, // Enviamos directamente el token FCM
		"title":     "Nueva solicitud de colaboración",
		"message":   fmt.Sprintf("%s quiere unirse a tu estación", requesterUsername),
		"data": map[string]string{
			"type":         "collaboration_request",
			"station_id":   strconv.Itoa(stationID),
			"request_id":   strconv.FormatInt(requestID, 10),
			"requester":    requesterUsername,
			"click_action": "FLUTTER_NOTIFICATION_CLICK", // Para manejar clics en Flutter
		},
	}

	jsonData, err := json.Marshal(notification)
	if err != nil {
		log.Printf("Error creando JSON de notificación: %v", err)
		return
	}

	messagingAPIURL := "http://127.0.0.1:8081/send-notification"
	resp, err := http.Post(messagingAPIURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error llamando a API de mensajería: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("API de mensajería respondió con error %d: %s", resp.StatusCode, string(body))
	}
}

func getRequestsByStation(w http.ResponseWriter, r *http.Request) { //CAMBIADO POR EL BIEN DE LA TRAMA
	params := mux.Vars(r)
	stationID := parseID(params["station_id"])

	rows, err := db.Query("SELECT id, user_id, station_id, status FROM requests WHERE station_id = ? AND status = 'pending'", stationID)
	if err != nil {
		http.Error(w, "Error fetching requests", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var requests []RequestWithUser
	for rows.Next() {
		var req RequestWithUser
		if err := rows.Scan(&req.ID, &req.UserID, &req.StationID, &req.Status); err != nil {
			http.Error(w, "Error scanning requests", http.StatusInternalServerError)
			return
		}

		// Obtener usuario por user_id
		var user User
		var image, token, token2 sql.NullString

		err := db.QueryRow("SELECT id, username, email, password, image, token, token2 FROM users WHERE id = ?", req.UserID).Scan(
			&user.ID, &user.Username, &user.Email, &user.Password, &image, &token, &token2)

		if err != nil {
			log.Println("Error al obtener usuario:", err) // Loguea el error exacto
			user = User{}                                 // Si falla, asigna un usuario vacío
		}

		// Manejo de NULL para strings
		user.Image = ""
		if image.Valid {
			user.Image = image.String
		}
		user.Token = ""
		if token.Valid {
			user.Token = token.String
		}
		user.Token2 = ""
		if token2.Valid {
			user.Token2 = token2.String
		}

		// Asignar usuario a la respuesta
		req.User = user
		requests = append(requests, req)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(requests)
}

func updateRequestStatus(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var req Request
	json.NewDecoder(r.Body).Decode(&req)
	req.ID = parseID(params["id"])

	tx, err := db.Begin()
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Primero obtenemos los datos necesarios para la notificación
	var requestInfo struct {
		UserID      int
		StationID   int
		StationName string
	}

	err = tx.QueryRow(`
        SELECT r.user_id, r.station_id, s.name 
        FROM requests r
        JOIN stations s ON r.station_id = s.id
        WHERE r.id = ?`, req.ID).Scan(
		&requestInfo.UserID,
		&requestInfo.StationID,
		&requestInfo.StationName)
	if err != nil {
		http.Error(w, "Error obteniendo información de la solicitud", http.StatusInternalServerError)
		return
	}

	if req.Status == "accepted" {
		_, err = tx.Exec("INSERT INTO collaborators (user_id, station_id) SELECT user_id, station_id FROM requests WHERE id = ?", req.ID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	_, err = tx.Exec("UPDATE requests SET status = ? WHERE id = ?", req.Status, req.ID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tx.Commit()

	// Enviamos la notificación al usuario solicitante
	go sendRequestStatusNotification(requestInfo.UserID, req.ID, requestInfo.StationID, requestInfo.StationName, req.Status)

	w.WriteHeader(http.StatusOK)
}

func sendRequestStatusNotification(userID int, requestID int, stationID int, stationName string, status string) {
	// Obtener el token FCM del solicitante (token2) directamente
	var userToken string
	err := db.QueryRow("SELECT token2 FROM users WHERE id = ?", userID).Scan(&userToken)
	if err != nil || userToken == "" {
		log.Printf("No se pudo obtener token FCM del usuario %d: %v", userID, err)
		return
	}

	// Crear mensaje según el estado
	var title, message string
	if status == "accepted" {
		title = "Solicitud aceptada"
		message = fmt.Sprintf("Tu solicitud para la estación %s ha sido aceptada", stationName)
	} else {
		title = "Solicitud rechazada"
		message = fmt.Sprintf("Tu solicitud para la estación %s ha sido rechazada", stationName)
	}

	notification := map[string]interface{}{
		"fcm_token": userToken,
		"title":     title,
		"message":   message,
		"data": map[string]string{
			"type":         "request_status_update",
			"station_id":   strconv.Itoa(stationID),
			"request_id":   strconv.Itoa(requestID),
			"status":       status,
			"click_action": "FLUTTER_NOTIFICATION_CLICK",
		},
	}

	jsonData, err := json.Marshal(notification)
	if err != nil {
		log.Printf("Error creando JSON de notificación: %v", err)
		return
	}

	messagingAPIURL := "http://127.0.0.1:8081/send-notification"
	resp, err := http.Post(messagingAPIURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error llamando a API de mensajería: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("API de mensajería respondió con error %d: %s", resp.StatusCode, string(body))
	}
}

func parseID(idStr string) int {
	var id int
	fmt.Sscanf(idStr, "%d", &id)
	return id
}

// -----------------------
func createUser(w http.ResponseWriter, r *http.Request) {
	// Limitar el tamaño del cuerpo para evitar ataques grandes
	r.ParseMultipartForm(10 << 20) // 10MB máximo

	var user User
	user.Username = r.FormValue("username")
	user.Email = r.FormValue("email")
	user.Password = r.FormValue("password")
	user.Token = r.FormValue("token")   // Nuevo campo
	user.Token2 = r.FormValue("token2") // Nuevo campo

	// Validar que los campos obligatorios estén presentes
	if user.Username == "" || user.Email == "" || user.Password == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("image")
	if err == nil { // Si la imagen se envió correctamente
		defer file.Close()

		// Asegurar que la carpeta "uploads" existe
		if _, err := os.Stat("uploads"); os.IsNotExist(err) {
			os.Mkdir("uploads", 0755)
		}

		// Crear el archivo en el servidor
		imagePath := "uploads/" + handler.Filename
		outFile, err := os.Create(imagePath)
		if err != nil {
			http.Error(w, "Error saving the image", http.StatusInternalServerError)
			return
		}
		defer outFile.Close()

		// Copiar el contenido de la imagen al nuevo archivo
		_, err = io.Copy(outFile, file)
		if err != nil {
			http.Error(w, "Error saving the image", http.StatusInternalServerError)
			return
		}

		// Guardar la ruta en el usuario
		user.Image = "http://127.0.0.1:8080/" + imagePath
	} else {
		log.Println("No image uploaded or error handling file:", err)
		user.Image = "" // Imagen opcional
	}
	// Insertar el usuario en la base de datos
	_, err = db.Exec("INSERT INTO users (username, email, password, image, token, token2) VALUES (?, ?, ?, ?, ?, ?)",
		user.Username, user.Email, user.Password, user.Image, nullIfEmpty(user.Token), nullIfEmpty(user.Token2))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}

// Función para convertir cadenas vacías en NULL
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func getUser(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	log.Println("ID recibido:", params["id"]) // Verifica que el ID se reciba correctamente

	var user User
	var image, token, token2 sql.NullString // Manejar valores NULL

	err := db.QueryRow("SELECT id, username, email, password, image, token, token2 FROM users WHERE id = ?", params["id"]).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password, &image, &token, &token2)

	if err != nil {
		log.Println("Error al obtener usuario:", err) // Loguea el error exacto
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Manejo de NULL para strings
	user.Image = image.String
	if !image.Valid {
		user.Image = "" // Valor por defecto si es NULL
	}
	user.Token = token.String
	if !token.Valid {
		user.Token = ""
	}

	user.Token2 = token2.String
	if !token2.Valid {
		user.Token2 = ""
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}
func getUserByToken2(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	log.Println("Token de google recibido:", params["token2"]) // Verifica que el ID se reciba correctamente

	var user User
	var image, token, token2 sql.NullString // Manejar valores NULL

	err := db.QueryRow("SELECT id, username, email, password, image, token, token2 FROM users WHERE token2 = ?", params["token2"]).Scan(
		&user.ID, &user.Username, &user.Email, &user.Password, &image, &token, &token2)

	if err != nil {
		log.Println("Error al obtener usuario:", err) // Loguea el error exacto
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Manejo de NULL para strings
	user.Image = image.String
	if !image.Valid {
		user.Image = "" // Valor por defecto si es NULL
	}

	user.Token = token.String
	if !token.Valid {
		user.Token = ""
	}

	user.Token2 = token2.String
	if !token2.Valid {
		user.Token2 = ""
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func createStation(w http.ResponseWriter, r *http.Request) {
	var station Station
	json.NewDecoder(r.Body).Decode(&station)
	_, err := db.Exec("INSERT INTO stations (name, latitude, longitude, owner_id, plan) VALUES (?, ?, ?, ?, ?)",
		station.Name, station.Latitude, station.Longitude, station.OwnerID, station.Plan)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func getStation(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var station StationWithOwner
	err := db.QueryRow(`
        SELECT s.id, s.name, s.latitude, s.longitude, s.owner_id, s.plan 
        FROM stations s 
        WHERE s.id = ?`, params["id"]).Scan(
		&station.ID, &station.Name, &station.Latitude, &station.Longitude, &station.OwnerID, &station.Plan)

	if err != nil {
		http.Error(w, "Station not found", http.StatusNotFound)
		return
	}

	// Ahora obtenemos la información del dueño
	var image, token, token2 sql.NullString
	err = db.QueryRow(`
        SELECT u.id, u.username, u.email, u.image, u.token, u.token2 
        FROM users u 
        WHERE u.id = ?`, station.OwnerID).Scan(
		&station.Owner.ID, &station.Owner.Username, &station.Owner.Email,
		&image, &token, &token2)

	if err != nil {
		http.Error(w, "Owner information not available", http.StatusInternalServerError)
		return
	}

	// Manejo de campos NULL como en tu implementación
	station.Owner.Image = image.String
	if !image.Valid {
		station.Owner.Image = ""
	}
	station.Owner.Token = token.String
	if !token.Valid {
		station.Owner.Token = ""
	}
	station.Owner.Token2 = token2.String
	if !token2.Valid {
		station.Owner.Token2 = ""
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(station)
}

func addCollaborator(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	var collaborator Collaborator
	json.NewDecoder(r.Body).Decode(&collaborator)

	var ownerPlan string
	err := db.QueryRow("SELECT plan FROM stations WHERE id = ?", params["station_id"]).Scan(&ownerPlan)
	if err != nil {
		http.Error(w, "Station not found", http.StatusNotFound)
		return
	}

	var count int
	db.QueryRow("SELECT COUNT(*) FROM collaborators WHERE station_id = ?", params["station_id"]).Scan(&count)

	maxCollaborators := 10
	if ownerPlan == "basic+" {
		maxCollaborators = 100
	}

	if count >= maxCollaborators {
		http.Error(w, "Maximum number of collaborators reached", http.StatusForbidden)
		return
	}

	_, err = db.Exec("INSERT INTO collaborators (user_id, station_id) VALUES (?, ?)",
		collaborator.UserID, collaborator.StationID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// Función para obtener todos los colaboradores de una estación
func getCollaboratorsByStation(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	stationID := params["station_id"]

	// Consultar la estación
	var station Station
	err := db.QueryRow("SELECT id, name, latitude, longitude, owner_id, plan FROM stations WHERE id = ?", stationID).Scan(
		&station.ID, &station.Name, &station.Latitude, &station.Longitude, &station.OwnerID, &station.Plan)
	if err != nil {
		http.Error(w, "Station not found", http.StatusNotFound)
		return
	}

	// Consultar los colaboradores y la información del usuario (incluyendo la imagen)
	rows, err := db.Query(`
		SELECT c.id, c.user_id, c.station_id, u.username, u.image 
		FROM collaborators c 
		JOIN users u ON c.user_id = u.id 
		WHERE c.station_id = ?`, stationID)
	if err != nil {
		http.Error(w, "Error fetching collaborators", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var collaborators []CollaboratorWithUser
	for rows.Next() {
		var collaborator CollaboratorWithUser
		if err := rows.Scan(&collaborator.ID, &collaborator.UserID, &collaborator.StationID, &collaborator.Username, &collaborator.Image); err != nil {
			http.Error(w, "Error scanning collaborators", http.StatusInternalServerError)
			return
		}
		collaborators = append(collaborators, collaborator)
	}

	// Verificar si no se encontraron colaboradores
	if len(collaborators) == 0 {
		http.Error(w, "No collaborators found for this station", http.StatusNotFound)
		return
	}

	// Crear la respuesta con los colaboradores y los datos de la estación
	response := CollaboratorsWithStation{
		Collaborators: collaborators,
		Station:       station,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// -------------
// busqueda de estaciones por usuarios
func getStationsByUserID(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	userID := parseID(params["id"])

	rows, err := db.Query("SELECT id, name, latitude, longitude, owner_id, plan FROM stations WHERE owner_id = ?", userID)
	if err != nil {
		http.Error(w, "Error fetching stations", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var stations []Station
	for rows.Next() {
		var station Station
		if err := rows.Scan(&station.ID, &station.Name, &station.Latitude, &station.Longitude, &station.OwnerID, &station.Plan); err != nil {
			http.Error(w, "Error scanning stations", http.StatusInternalServerError)
			return
		}
		stations = append(stations, station)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stations)
}

func getStationsByUserToken2(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	token2 := params["token2"]

	rows, err := db.Query("SELECT s.id, s.name, s.latitude, s.longitude, s.owner_id, s.plan FROM stations s JOIN users u ON s.owner_id = u.id WHERE u.token2 = ?", token2)
	if err != nil {
		http.Error(w, "Error fetching stations", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var stations []Station
	for rows.Next() {
		var station Station
		if err := rows.Scan(&station.ID, &station.Name, &station.Latitude, &station.Longitude, &station.OwnerID, &station.Plan); err != nil {
			http.Error(w, "Error scanning stations", http.StatusInternalServerError)
			return
		}
		stations = append(stations, station)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stations)
}

// -------------
func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	initDB()
	r := mux.NewRouter()

	// Middleware CORS antes de definir las rutas
	r.Use(enableCORS)

	// Manejar solicitudes OPTIONS globalmente
	r.Methods("OPTIONS").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Definir rutas
	r.HandleFunc("/users", createUser).Methods("POST")
	r.HandleFunc("/users/{id}", getUser).Methods("GET")
	r.HandleFunc("/users/token/{token2}", getUserByToken2).Methods("GET")
	r.HandleFunc("/stations", createStation).Methods("POST")
	r.HandleFunc("/stations/{id}", getStation).Methods("GET")
	r.HandleFunc("/users/{id}/stations", getStationsByUserID).Methods("GET")
	r.HandleFunc("/users/token/{token2}/stations", getStationsByUserToken2).Methods("GET")
	r.HandleFunc("/stations/{station_id}/collaborators", addCollaborator).Methods("POST")
	r.HandleFunc("/stations/{station_id}/collaborators", getCollaboratorsByStation).Methods("GET")
	r.HandleFunc("/stations/{station_id}/requests", createRequest).Methods("POST")
	r.HandleFunc("/stations/{station_id}/requests", getRequestsByStation).Methods("GET")
	r.HandleFunc("/requests/{id}", updateRequestStatus).Methods("PUT")
	r.HandleFunc("/users/{user_id}/stations-with-collaborators", getStationsWithCollaborators).Methods("GET")

	//Imagenes
	r.PathPrefix("/uploads/").Handler(http.StripPrefix("/uploads/", http.FileServer(http.Dir("uploads"))))

	log.Println("Server started on :8088")
	http.ListenAndServe(":8088", r)
}
