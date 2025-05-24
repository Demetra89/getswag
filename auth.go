package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	authDir       = "auth"
	userFile      = "user.json"
	sessionFile   = "session.json"
	maxSessionAge = time.Hour // Сессия действительна 1 час
)

// UserProfile представляет профиль пользователя
type UserProfile struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
	CreatedAt    int64  `json:"created_at"`
	LastLogin    int64  `json:"last_login"`
}

// SessionData представляет данные сессии
type SessionData struct {
	Username  string `json:"username"`
	SessionID string `json:"session_id"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	IPAddress string `json:"ip_address"`
}

// AuthMessage представляет сообщение авторизации
type AuthMessage struct {
	Type      string `json:"type"` // "auth_request", "auth_response", "auth_challenge"
	Username  string `json:"username"`
	Challenge string `json:"challenge,omitempty"`
	Response  string `json:"response,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

var (
	currentSession *SessionData
)

// initAuth инициализирует систему авторизации
func initAuth() error {
	log.Println("Инициализация системы авторизации")

	// Создаем директорию для авторизации, если она не существует
	if err := os.MkdirAll(authDir, 0700); err != nil {
		log.Printf("Ошибка создания директории для авторизации: %v", err)
		return err
	}

	// Пытаемся загрузить существующую сессию
	if session, err := loadSession(); err == nil {
		if time.Now().Unix() <= session.ExpiresAt {
			if user, err := loadUserProfile(session.Username); err == nil {
				currentSession = session
				log.Printf("Восстановлена сессия для пользователя: %s", user.Username)
			}
		} else {
			// Удаляем истекшую сессию
			clearSession()
		}
	}

	log.Println("Система авторизации инициализирована")
	return nil
}

// registerUser регистрирует нового пользователя
func registerUser(username, password string) error {
	if len(username) < 3 {
		return fmt.Errorf("имя пользователя должно содержать минимум 3 символа")
	}

	if len(password) < 6 {
		return fmt.Errorf("пароль должен содержать минимум 6 символов")
	}

	// Проверяем, существует ли уже пользователь
	userPath := filepath.Join(authDir, username+"_"+userFile)
	if _, err := os.Stat(userPath); err == nil {
		return fmt.Errorf("пользователь с таким именем уже существует")
	}

	// Генерируем соль
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("ошибка генерации соли: %v", err)
	}

	// Хешируем пароль с солью
	passwordHash := hashPassword(password, hex.EncodeToString(salt))

	// Создаем профиль пользователя
	user := UserProfile{
		Username:     username,
		PasswordHash: passwordHash,
		Salt:         hex.EncodeToString(salt),
		CreatedAt:    time.Now().Unix(),
		LastLogin:    0,
	}

	// Сохраняем профиль
	return saveUserProfile(&user)
}

// loginUser авторизует пользователя
func loginUser(username, password string) error {
	// Загружаем профиль пользователя
	user, err := loadUserProfile(username)
	if err != nil {
		return fmt.Errorf("пользователь не найден")
	}

	// Проверяем пароль
	expectedHash := hashPassword(password, user.Salt)
	if expectedHash != user.PasswordHash {
		return fmt.Errorf("неверный пароль")
	}

	// Обновляем время последнего входа
	user.LastLogin = time.Now().Unix()
	if err := saveUserProfile(user); err != nil {
		log.Printf("Ошибка обновления времени входа: %v", err)
	}

	// Создаем сессию
	session, err := createSession(username)
	if err != nil {
		return fmt.Errorf("ошибка создания сессии: %v", err)
	}

	currentSession = session

	log.Printf("Пользователь %s успешно авторизован", username)
	return nil
}

// createSession создает новую сессию для пользователя
func createSession(username string) (*SessionData, error) {
	// Генерируем случайный ID сессии
	sessionBytes := make([]byte, 32)
	if _, err := rand.Read(sessionBytes); err != nil {
		return nil, err
	}

	sessionID := hex.EncodeToString(sessionBytes)
	now := time.Now()

	session := &SessionData{
		Username:  username,
		SessionID: sessionID,
		CreatedAt: now.Unix(),
		ExpiresAt: now.Add(maxSessionAge).Unix(),
		IPAddress: getLocalIP(),
	}

	// Сохраняем сессию
	if err := saveSession(session); err != nil {
		return nil, err
	}

	return session, nil
}

// validateSession проверяет действительность сессии
func validateSession() bool {
	if currentSession == nil {
		return false
	}

	// Проверяем срок действия сессии
	if time.Now().Unix() > currentSession.ExpiresAt {
		log.Println("Сессия истекла")
		clearSession()
		return false
	}

	return true
}

// clearSession очищает текущую сессию
func clearSession() {
	currentSession = nil

	// Удаляем файл сессии
	sessionPath := filepath.Join(authDir, sessionFile)
	os.Remove(sessionPath)
}

// saveUserProfile сохраняет профиль пользователя
func saveUserProfile(user *UserProfile) error {
	userPath := filepath.Join(authDir, user.Username+"_"+userFile)

	userJSON, err := json.MarshalIndent(user, "", "  ")
	if err != nil {
		return fmt.Errorf("ошибка сериализации профиля: %v", err)
	}

	err = os.WriteFile(userPath, userJSON, 0600)
	if err != nil {
		return fmt.Errorf("ошибка сохранения профиля: %v", err)
	}

	return nil
}

// loadUserProfile загружает профиль пользователя
func loadUserProfile(username string) (*UserProfile, error) {
	userPath := filepath.Join(authDir, username+"_"+userFile)

	data, err := os.ReadFile(userPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения профиля: %v", err)
	}

	var user UserProfile
	err = json.Unmarshal(data, &user)
	if err != nil {
		return nil, fmt.Errorf("ошибка десериализации профиля: %v", err)
	}

	return &user, nil
}

// saveSession сохраняет сессию
func saveSession(session *SessionData) error {
	sessionPath := filepath.Join(authDir, sessionFile)

	sessionJSON, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return fmt.Errorf("ошибка сериализации сессии: %v", err)
	}

	err = os.WriteFile(sessionPath, sessionJSON, 0600)
	if err != nil {
		return fmt.Errorf("ошибка сохранения сессии: %v", err)
	}

	return nil
}

// loadSession загружает сохраненную сессию
func loadSession() (*SessionData, error) {
	sessionPath := filepath.Join(authDir, sessionFile)

	data, err := os.ReadFile(sessionPath)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения сессии: %v", err)
	}

	var session SessionData
	err = json.Unmarshal(data, &session)
	if err != nil {
		return nil, fmt.Errorf("ошибка десериализации сессии: %v", err)
	}

	return &session, nil
}

// hashPassword создает хеш пароля с солью
func hashPassword(password, salt string) string {
	hash := sha256.New()
	hash.Write([]byte(password + salt))
	return hex.EncodeToString(hash.Sum(nil))
}

// getLocalIP получает локальный IP адрес
func getLocalIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

// authenticateWithPeer выполняет аутентификацию с пиром
func authenticateWithPeer(peerAddress string) error {
	if currentSession == nil {
		return nil
	}

	// Генерируем вызов для аутентификации
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return fmt.Errorf("ошибка генерации вызова: %v", err)
	}

	challengeStr := hex.EncodeToString(challenge)

	// Создаем сообщение аутентификации
	authMsg := AuthMessage{
		Type:      "auth_challenge",
		Username:  currentSession.Username,
		Challenge: challengeStr,
		SessionID: currentSession.SessionID,
		Timestamp: time.Now().Unix(),
	}

	// Отправляем вызов пиру
	msgJSON, err := json.Marshal(authMsg)
	if err != nil {
		return fmt.Errorf("ошибка сериализации сообщения аутентификации: %v", err)
	}

	// Предполагается, что функция sendTCPData определена в другом файле
	// return sendTCPData(peerAddress, tcpPort, msgJSON)
	log.Printf("Отправка аутентификации пиру %s: %s", peerAddress, string(msgJSON))
	return nil
}

// handleAuthMessage обрабатывает сообщения аутентификации
func handleAuthMessage(message []byte, peerAddress string) error {
	var authMsg AuthMessage
	if err := json.Unmarshal(message, &authMsg); err != nil {
		return fmt.Errorf("ошибка десериализации сообщения аутентификации: %v", err)
	}

	switch authMsg.Type {
	case "auth_challenge":
		return respondToAuthChallenge(authMsg, peerAddress)
	case "auth_response":
		return validateAuthResponse(authMsg, peerAddress)
	default:
		return fmt.Errorf("неизвестный тип сообщения аутентификации: %s", authMsg.Type)
	}
}

// respondToAuthChallenge отвечает на запрос авторизации
func respondToAuthChallenge(authMsg AuthMessage, peerAddress string) error {
	if !validateSession() {
		return fmt.Errorf("недействительная сессия")
	}

	// Создаем ответ на запрос (подписываем своим приватным ключом)
	response := hashPassword(authMsg.Challenge, currentSession.SessionID)

	// Отправляем ответ
	responseMsg := AuthMessage{
		Type:      "auth_response",
		Username:  currentSession.Username,
		Response:  response,
		SessionID: currentSession.SessionID,
		Timestamp: time.Now().Unix(),
	}

	msgJSON, err := json.Marshal(responseMsg)
	if err != nil {
		return fmt.Errorf("ошибка сериализации ответа: %v", err)
	}

	// Предполагается, что функция sendTCPData определена в другом файле
	// return sendTCPData(peerAddress, tcpPort, msgJSON)
	log.Printf("Отправка ответа авторизации пиру %s: %s", peerAddress, string(msgJSON))
	return nil
}

// validateAuthResponse проверяет ответ на запрос авторизации
func validateAuthResponse(authMsg AuthMessage, peerAddress string) error {
	// Эта функция используется в handleAuthMessage
	// ... код функции ...
	return nil
}

// checkUserExists проверяет существование пользователя
func checkUserExists(username string) bool {
	userPath := filepath.Join(authDir, username+"_"+userFile)
	_, err := os.Stat(userPath)
	return err == nil
}

// listUsers возвращает список зарегистрированных пользователей
func listUsers() ([]string, error) {
	files, err := filepath.Glob(filepath.Join(authDir, "*_"+userFile))
	if err != nil {
		return nil, err
	}

	var users []string
	for _, file := range files {
		basename := filepath.Base(file)
		username := strings.TrimSuffix(basename, "_"+userFile)
		users = append(users, username)
	}

	return users, nil
}

// getCurrentUser возвращает текущую сессию пользователя
func getCurrentUser() *SessionData {
	return currentSession
}

// isAuthenticated проверяет, авторизован ли пользователь
func isAuthenticated() bool {
	return currentSession != nil && validateSession()
}

// logoutUser выполняет выход пользователя из системы
func logoutUser() {
	if currentSession != nil {
		log.Printf("Пользователь %s вышел из системы", currentSession.Username)
	}
	clearSession()
}

// updatePassword обновляет пароль пользователя
func updatePassword(username, oldPassword, newPassword string) error {
	if len(newPassword) < 6 {
		return fmt.Errorf("новый пароль должен содержать минимум 6 символов")
	}

	// Проверяем старый пароль
	user, err := loadUserProfile(username)
	if err != nil {
		return fmt.Errorf("пользователь не найден")
	}

	expectedHash := hashPassword(oldPassword, user.Salt)
	if expectedHash != user.PasswordHash {
		return fmt.Errorf("неверный старый пароль")
	}

	// Генерируем новую соль
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("ошибка генерации соли: %v", err)
	}

	// Обновляем пароль
	user.PasswordHash = hashPassword(newPassword, hex.EncodeToString(salt))
	user.Salt = hex.EncodeToString(salt)

	return saveUserProfile(user)
}

// verifyPassword проверяет соответствие пароля хешу
func verifyPassword(password string, hash string) bool {
	// Загружаем профиль пользователя для получения соли
	parts := strings.Split(hash, ":")
	if len(parts) != 2 {
		return false
	}

	hashedPassword := hashPassword(password, parts[0])
	return hashedPassword == parts[1]
}

// validateCredentials проверяет учетные данные пользователя
func validateCredentials(username string, password string) bool {
	// Загружаем профиль пользователя
	user, err := loadUserProfile(username)
	if err != nil {
		return false
	}

	// Проверяем пароль
	expectedHash := hashPassword(password, user.Salt)
	return expectedHash == user.PasswordHash
}
