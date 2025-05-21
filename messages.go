package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// Message определяет структуру сообщения
type Message struct {
	Type      string `json:"type"`      // Тип сообщения: "message", "pubkey", и т.д.
	Sender    string `json:"sender"`    // Имя отправителя
	Content   string `json:"content"`   // Зашифрованное или открытое содержимое
	Timestamp int64  `json:"timestamp"` // Временная метка
}

// startTCPServer запускает TCP сервер для приема сообщений
func startTCPServer() {
	log.Println("Запуск TCP сервера для приема сообщений")

	// Слушаем на всех интерфейсах
	addr := net.JoinHostPort("", fmt.Sprintf("%d", tcpPort))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Ошибка запуска TCP сервера: %v", err)
		fmt.Printf("\nОшибка запуска TCP сервера: %v\n", err)
		return
	}
	defer listener.Close()

	log.Printf("TCP сервер запущен на порту %d", tcpPort)
	fmt.Printf("\nTCP сервер запущен на порту %d\n", tcpPort)

	for running {
		conn, err := listener.Accept()
		if err != nil {
			if !running {
				break
			}
			log.Printf("Ошибка принятия соединения: %v", err)
			continue
		}
		go handleTCPConnection(conn)
	}
}

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("Получено TCP соединение от %s", remoteAddr)

	// Буфер для чтения данных
	buffer := make([]byte, maxMessageSize)
	n, err := conn.Read(buffer)
	if err != nil {
		if err != io.EOF {
			log.Printf("Ошибка чтения из соединения %s: %v", remoteAddr, err)
		}
		return
	}

	// Декодируем сообщение
	var message Message
	err = json.Unmarshal(buffer[:n], &message)
	if err != nil {
		log.Printf("Ошибка декодирования сообщения от %s: %v", remoteAddr, err)
		return
	}

	// Получаем IP отправителя
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		log.Printf("Ошибка извлечения адреса из %s: %v", remoteAddr, err)
		return
	}

	// Проверяем известен ли отправитель
	peersMutex.RLock()
	_, knownPeer := peers[host] // Используем переменную `peer` для проверки
	peersMutex.RUnlock()

	if !knownPeer {
		log.Printf("Получено сообщение от неизвестного пира: %s", host)
		return
	}

	// Обрабатываем сообщение в зависимости от типа
	switch message.Type {
	case "message":
		// Расшифровываем сообщение
		content, err := decryptMessage(message.Content)
		if err != nil {
			log.Printf("Ошибка расшифровки сообщения: %v", err)
			return
		}

		log.Printf("Получено сообщение от %s: %s", message.Sender, content)

		// Отображаем сообщение
		if uiEnabled {
			// Для UI режима обновляем список сообщений
			uiAddMessage(message.Sender, username, content, message.Timestamp)
		} else {
			// Для консольного режима выводим сообщение
			fmt.Printf("\nСообщение от %s: %s\n", message.Sender, content)
			printPrompt()
		}

		// Сохраняем сообщение в базу данных
		if dbEnabled {
			saveMessage(message.Sender, username, content, message.Timestamp)
		}

	case "pubkey":
		log.Printf("Получен запрос публичного ключа от %s", host)
		// Отправляем публичный ключ в ответ
		sendPublicKey(host)

	default:
		log.Printf("Получено сообщение неизвестного типа: %s", message.Type)
	}
}

// sendMessage отправляет сообщение указанному пиру по имени
func sendMessage(peerName, content string) {
	log.Printf("Отправка сообщения пиру %s", peerName)

	// Находим пира по имени
	var peerAddress string
	var targetPeer Peer

	peersMutex.RLock()
	for addr, peer := range peers {
		if peer.Name == peerName {
			peerAddress = addr
			targetPeer = peer
			break
		}
	}
	peersMutex.RUnlock()

	if peerAddress == "" {
		log.Printf("Пир %s не найден", peerName)
		fmt.Printf("\nПир %s не найден\n", peerName)
		printPrompt()
		return
	}

	// Используем targetPeer, например, для логирования
	log.Printf("Найден пир %s с адресом %s", targetPeer.Name, peerAddress)

	// Отправляем сообщение
	err := sendEncryptedMessage(peerAddress, content)
	if err != nil {
		log.Printf("Ошибка отправки сообщения: %v", err)
		fmt.Printf("\nОшибка отправки сообщения: %v\n", err)
		printPrompt()
		return
	}

	// Сохраняем сообщение в базу данных
	timestamp := time.Now().Unix()
	if dbEnabled {
		saveMessage(username, peerName, content, timestamp)
	}

	// Выводим подтверждение только в консольном режиме
	if !uiEnabled {
		fmt.Printf("\nСообщение отправлено %s: %s\n", peerName, content)
		printPrompt()
	}
}

// sendEncryptedMessage шифрует и отправляет сообщение по указанному адресу
func sendEncryptedMessage(peerAddress, content string) error {
	peersMutex.RLock()
	peer, exists := peers[peerAddress]
	peersMutex.RUnlock()

	if !exists {
		return fmt.Errorf("пир не найден")
	}

	// Проверяем наличие публичного ключа
	if peer.PublicKey == nil {
		return fmt.Errorf("публичный ключ пира не доступен")
	}

	// Шифруем сообщение
	encryptedContent, err := encryptMessage(content, peer.PublicKey)
	if err != nil {
		return fmt.Errorf("ошибка шифрования: %v", err)
	}

	// Формируем сообщение
	message := Message{
		Type:      "message",
		Sender:    username,
		Content:   encryptedContent,
		Timestamp: time.Now().Unix(),
	}

	// Сериализуем сообщение
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("ошибка сериализации: %v", err)
	}

	// Отправляем сообщение
	return sendTCPData(peerAddress, tcpPort, messageJSON)
}

// sendPublicKey отправляет публичный ключ по указанному адресу
func sendPublicKey(peerAddress string) error {
	// Получаем PEM представление публичного ключа
	pubKeyPEM := getPublicKeyPEM()

	// Формируем сообщение
	message := Message{
		Type:      "pubkey",
		Sender:    username,
		Content:   pubKeyPEM,
		Timestamp: time.Now().Unix(),
	}

	// Сериализуем сообщение
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("ошибка сериализации: %v", err)
	}

	// Отправляем сообщение
	return sendTCPData(peerAddress, tcpPort, messageJSON)
}

// sendTCPData отправляет данные по TCP на указанный адрес
func sendTCPData(ip string, port int, data []byte) error {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("ошибка соединения с %s: %v", addr, err)
	}
	defer conn.Close()

	// Отправляем данные
	_, err = conn.Write(data)
	if err != nil {
		return fmt.Errorf("ошибка отправки данных: %v", err)
	}

	return nil
}

// encryptMessage шифрует сообщение с использованием RSA-OAEP
func encryptMessage(message string, publicKey *rsa.PublicKey) (string, error) {
	// Используем SHA-256 для хеширования в OAEP
	hash := sha256.New()

	// Шифруем сообщение
	encryptedMsg, err := rsa.EncryptOAEP(
		hash,
		rand.Reader,
		publicKey,
		[]byte(message),
		nil,
	)
	if err != nil {
		return "", err
	}

	// Кодируем результат в base64
	return base64.StdEncoding.EncodeToString(encryptedMsg), nil
}

// decryptMessage расшифровывает сообщение с использованием RSA-OAEP
func decryptMessage(encryptedBase64 string) (string, error) {
	// Декодируем из base64
	encryptedMsg, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", fmt.Errorf("ошибка декодирования base64: %v", err)
	}

	// Используем SHA-256 для хеширования в OAEP
	hash := sha256.New()

	// Расшифровываем сообщение приватным ключом
	decryptedMsg, err := rsa.DecryptOAEP(
		hash,
		rand.Reader,
		privateKey,
		encryptedMsg,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("ошибка расшифровки: %v", err)
	}

	return string(decryptedMsg), nil
}
