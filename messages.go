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
	"runtime"
	"sync"
	"time"
)

// Message определяет структуру сообщения
type Message struct {
	Type      string `json:"type"`                 // Тип сообщения: "message", "pubkey", "heartbeat", "auth", и т.д.
	Sender    string `json:"sender"`               // Имя отправителя
	Content   string `json:"content"`              // Зашифрованное или открытое содержимое
	Timestamp int64  `json:"timestamp"`            // Временная метка
	SessionID string `json:"session_id,omitempty"` // ID сессии для авторизации
}

var (
	// Карта для отслеживания имен пользователей
	usernameMutex sync.RWMutex
	usernameMap   = make(map[string]string) // имя -> IP адрес

	// Карта для отслеживания активных соединений
	connectionsMutex  sync.RWMutex
	activeConnections = make(map[string]net.Conn) // IP адрес -> соединение

	// Канал для сигнализации о переподключении
	reconnectChan = make(chan string, 10)

	// Сетевые переменные (перенесены из main.go)
	// Уже объявлены там, поэтому здесь не дублируем
	// networkMutex sync.RWMutex
	// tcpListener net.Listener
)

// startTCPServer запускает TCP сервер для приема сообщений
func startTCPServer() {
	log.Println("Запуск TCP сервера для приема сообщений")

	// Попытаемся использовать несколько портов, если основной занят
	var err error
	maxRetries := 3
	portOffset := 0
	var currentPort int

	for i := 0; i < maxRetries; i++ {
		currentPort = tcpPort + portOffset
		currentAddr := net.JoinHostPort("", fmt.Sprintf("%d", currentPort))

		// Защита от одновременного доступа
		networkMutex.Lock()
		tcpListener, err = net.Listen("tcp", currentAddr)
		networkMutex.Unlock()

		if err == nil {
			// Порт успешно занят
			log.Printf("TCP сервер успешно запущен на порту %d", currentPort)
			fmt.Printf("\nTCP сервер запущен на порту %d\n", currentPort)

			// Если порт изменился, фиксируем это (хотя мы не можем изменить саму константу)
			if portOffset > 0 {
				log.Printf("Внимание: TCP порт изменен с %d на %d", tcpPort, currentPort)
			}

			break
		}

		log.Printf("Не удалось запустить TCP сервер на порту %d: %v, попытка %d",
			currentPort, err, i+1)
		portOffset++
	}

	// Если после всех попыток не удалось запустить, сообщаем об ошибке
	if err != nil {
		log.Printf("Ошибка запуска TCP сервера после %d попыток: %v", maxRetries, err)
		fmt.Printf("\nОшибка запуска TCP сервера: %v\n", err)
		return
	}

	// Запускаем обработчик переподключений в отдельной горутине
	go handleReconnects()

	// Горутина для обработки входящих соединений
	go func() {
		for running {
			// Используем глобальную переменную вместо локальной
			conn, err := tcpListener.Accept()
			if err != nil {
				if !running {
					break
				}
				log.Printf("Ошибка принятия соединения: %v", err)
				continue
			}
			go handleTCPConnection(conn)
		}
	}()
}

// handleReconnects обрабатывает переподключения пиров
func handleReconnects() {
	for running {
		// Заменяем select с одним case на прямое чтение из канала
		peerAddr := <-reconnectChan
		log.Printf("Обработка переподключения для %s", peerAddr)

		// Проверяем, существует ли пир
		peersMutex.RLock()
		peer, exists := peers[peerAddr]
		peersMutex.RUnlock()

		if !exists {
			log.Printf("Пир %s не найден для переподключения", peerAddr)
			continue
		}

		// Запрашиваем публичный ключ заново
		log.Printf("Запрос публичного ключа для переподключения к %s", peer.Name)
		sendPublicKeyRequest(peerAddr)

		// Отправляем информацию о себе
		log.Printf("Отправка информации о себе при переподключении к %s", peer.Name)
		sendAuthInfo(peerAddr)
	}
}

func handleTCPConnection(conn net.Conn) {
	// Добавляем защиту от паники
	defer func() {
		if r := recover(); r != nil {
			log.Printf("КРИТИЧЕСКАЯ ОШИБКА: Паника при обработке TCP соединения: %v", r)
			// Запись стека вызовов для отладки
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			log.Printf("Стек вызовов: %s", buf[:n])
		}
		conn.Close()
		log.Printf("Соединение с %s закрыто", conn.RemoteAddr().String())
	}()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("Получено TCP соединение от %s", remoteAddr)

	// Получаем IP отправителя
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		log.Printf("Ошибка извлечения адреса из %s: %v", remoteAddr, err)
		return
	}

	// Сохраняем соединение в карту активных соединений
	connectionsMutex.Lock()
	activeConnections[host] = conn
	connectionsMutex.Unlock()

	// Буфер для чтения данных
	buffer := make([]byte, maxMessageSize)

	for running {
		// Устанавливаем таймаут чтения
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		n, err := conn.Read(buffer)
		if err != nil {
			if err == io.EOF || !running {
				break
			}

			// Проверяем, является ли ошибка таймаутом
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Это нормально, просто продолжаем ожидание
				continue
			}

			log.Printf("Ошибка чтения из соединения %s: %v", remoteAddr, err)
			break
		}

		// Обновляем время последней активности пира
		updatePeerActivity(host)

		// Декодируем сообщение
		var message Message
		err = json.Unmarshal(buffer[:n], &message)
		if err != nil {
			log.Printf("Ошибка декодирования сообщения от %s: %v", remoteAddr, err)
			continue
		}

		// Обрабатываем сообщение в зависимости от типа
		switch message.Type {
		case "message":
			// Оборачиваем в защитный блок
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("КРИТИЧЕСКАЯ ОШИБКА при обработке сообщения от %s: %v", host, r)
						buf := make([]byte, 2048)
						n := runtime.Stack(buf, false)
						log.Printf("Стек вызовов: %s", buf[:n])
					}
				}()
				handleMessagePacket(message, host)
			}()
		case "pubkey":
			handlePublicKeyPacket(message, host)
		case "pubkey_request":
			handlePublicKeyRequest(host)
		case "heartbeat":
			handleHeartbeatPacket(message, host)
		case "auth":
			handleAuthPacket(message, host)
		default:
			log.Printf("Получено сообщение неизвестного типа: %s", message.Type)
		}
	}

	// Удаляем соединение из карты активных соединений
	connectionsMutex.Lock()
	delete(activeConnections, host)
	connectionsMutex.Unlock()
}

// handleMessagePacket обрабатывает пакет с сообщением
func handleMessagePacket(message Message, host string) {
	// Добавляем защиту от паники
	defer func() {
		if r := recover(); r != nil {
			log.Printf("КРИТИЧЕСКАЯ ОШИБКА при обработке сообщения: %v", r)
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			log.Printf("Стек вызовов: %s", buf[:n])
		}
	}()

	// Проверяем известен ли отправитель
	peersMutex.RLock()
	peer, knownPeer := peers[host]
	peersMutex.RUnlock()

	if !knownPeer {
		log.Printf("Получено сообщение от неизвестного пира: %s", host)
		// Запрашиваем информацию о пире
		reconnectChan <- host
		return
	}

	// Расшифровываем сообщение
	content, err := decryptMessage(message.Content)
	if err != nil {
		log.Printf("Ошибка расшифровки сообщения: %v", err)
		return
	}

	log.Printf("Получено сообщение от %s: %s", message.Sender, content)

	// Проверяем соответствие имени отправителя
	if message.Sender != peer.Name {
		log.Printf("Несоответствие имени отправителя: получено от %s, ожидалось от %s",
			message.Sender, peer.Name)
	}

	// Создаем запись сообщения
	msgRecord := MessageRecord{
		Sender:    message.Sender,
		Recipient: username,
		Content:   content,
		Timestamp: message.Timestamp,
	}

	// Публикуем событие о новом сообщении
	GetEventBus().Publish(NetworkEvent{
		Type:    EventMessageReceived,
		Payload: msgRecord,
	})

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
}

// handlePublicKeyPacket обрабатывает пакет с публичным ключом
func handlePublicKeyPacket(message Message, host string) {
	log.Printf("Получен публичный ключ от %s (%s)", message.Sender, host)

	// Парсим публичный ключ
	pubKey := parsePublicKeyPEM(message.Content)
	if pubKey == nil {
		log.Printf("Ошибка парсинга публичного ключа от %s", host)
		return
	}

	// Проверяем уникальность имени
	usernameMutex.Lock()
	existingIP, exists := usernameMap[message.Sender]
	if exists && existingIP != host {
		log.Printf("Обнаружен конфликт имен: %s используется пиром %s, получено от %s",
			message.Sender, existingIP, host)
		// Здесь можно добавить логику разрешения конфликтов
	}
	usernameMap[message.Sender] = host
	usernameMutex.Unlock()

	// Обновляем информацию о пире
	peersMutex.Lock()
	peers[host] = Peer{
		Address:   host,
		Name:      message.Sender,
		PublicKey: pubKey,
		LastSeen:  time.Now(),
		IsOnline:  true,
	}
	peersMutex.Unlock()

	log.Printf("Обновлена информация о пире %s (%s)", message.Sender, host)

	// Обновляем UI
	if uiEnabled {
		// Безопасно обновляем UI
		safeUpdateUI()
	}

	// Сохраняем пира в базу данных
	if dbEnabled {
		savePeerInfo(peers[host])
	}

	// Отправляем свой публичный ключ в ответ
	sendPublicKey(host)

	// Отправляем информацию о себе для авторизации
	sendAuthInfo(host)
}

// handlePublicKeyRequest обрабатывает запрос публичного ключа
func handlePublicKeyRequest(host string) {
	log.Printf("Получен запрос публичного ключа от %s", host)
	sendPublicKey(host)
}

// handleHeartbeatPacket обрабатывает пакет heartbeat
func handleHeartbeatPacket(message Message, host string) {
	log.Printf("Получен heartbeat от %s (%s)", message.Sender, host)

	// Обновляем информацию о пире
	peersMutex.Lock()
	if peer, exists := peers[host]; exists {
		peer.LastSeen = time.Now()
		peer.IsOnline = true
		peers[host] = peer
	} else {
		// Если пир неизвестен, запрашиваем информацию о нем
		log.Printf("Получен heartbeat от неизвестного пира: %s", host)
		reconnectChan <- host
	}
	peersMutex.Unlock()
}

// handleAuthPacket обрабатывает пакет авторизации
func handleAuthPacket(message Message, host string) {
	log.Printf("Получена информация аутентификации от %s (%s)", message.Sender, host)

	// Проверяем уникальность имени
	usernameMutex.Lock()
	existingIP, exists := usernameMap[message.Sender]

	if exists && existingIP != host {
		log.Printf("Обнаружен конфликт имен: %s используется пиром %s, получено от %s",
			message.Sender, existingIP, host)
		// Здесь можно добавить логику разрешения конфликтов
	} else {
		usernameMap[message.Sender] = host
	}
	usernameMutex.Unlock()

	// Обновляем информацию о пире, если у нас есть его публичный ключ
	peersMutex.Lock()
	if peer, exists := peers[host]; exists {
		peer.Name = message.Sender
		peer.LastSeen = time.Now()
		peer.IsOnline = true
		peers[host] = peer

		log.Printf("Обновлена информация аутентификации для пира %s (%s)", message.Sender, host)
	} else {
		log.Printf("Получена информация аутентификации от пира без публичного ключа: %s", host)
		// Запрашиваем публичный ключ
		sendPublicKeyRequest(host)
	}
	peersMutex.Unlock()

	// Обновляем UI
	if uiEnabled {
		// Безопасно обновляем UI
		safeUpdateUI()
	}
}

// sendMessage отправляет сообщение указанному пиру по имени
func sendMessage(peerName, content string) {
	log.Printf("Отправка сообщения пиру %s", peerName)

	// Защита от паники
	defer func() {
		if r := recover(); r != nil {
			log.Printf("КРИТИЧЕСКАЯ ОШИБКА при отправке сообщения: %v", r)
			fmt.Printf("\nОшибка при отправке сообщения. Подробности в логе.\n")
			printPrompt()
		}
	}()

	// Находим пира по имени
	var peerAddress string
	var isOnline bool

	usernameMutex.RLock()
	for name, addr := range usernameMap {
		if name == peerName {
			peerAddress = addr

			// Проверяем, онлайн ли пир
			peersMutex.RLock()
			if peer, exists := peers[addr]; exists {
				isOnline = peer.IsOnline
			}
			peersMutex.RUnlock()

			break
		}
	}
	usernameMutex.RUnlock()

	if peerAddress == "" {
		log.Printf("Пир %s не найден", peerName)
		fmt.Printf("\nПир %s не найден\n", peerName)
		printPrompt()
		return
	}

	// Проверяем, находится ли пир в сети
	if !isOnline {
		log.Printf("Пир %s не в сети, обновляем статус", peerName)
		fmt.Printf("\nПир %s в данный момент не в сети. Проверка доступности...\n", peerName)

		// Проверяем соединение перед отправкой
		if !pingPeer(peerAddress) {
			log.Printf("Не удается установить соединение с пиром %s", peerName)
			fmt.Printf("Пир %s недоступен. Сообщение не может быть доставлено.\n", peerName)
			printPrompt()

			// Обновляем статус пира
			peersMutex.Lock()
			if peer, exists := peers[peerAddress]; exists {
				peer.IsOnline = false
				peers[peerAddress] = peer
				log.Printf("Статус пира %s обновлен на 'не в сети'", peerName)
			}
			peersMutex.Unlock()

			return
		} else {
			// Если соединение удалось, обновляем статус пира
			peersMutex.Lock()
			if peer, exists := peers[peerAddress]; exists {
				peer.IsOnline = true
				peer.LastSeen = time.Now()
				peers[peerAddress] = peer
				log.Printf("Статус пира %s обновлен на 'в сети'", peerName)
			}
			peersMutex.Unlock()

			fmt.Printf("Пир %s доступен, продолжаем отправку сообщения...\n", peerName)
		}
	}

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

// isPeerReachable проверяет, доступен ли пир для отправки сообщений
func pingPeer(peerAddress string) bool {
	// Добавляем защиту от ошибок
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Ошибка при проверке соединения с пиром: %v", r)
		}
	}()

	// Проверяем валидность адреса
	if peerAddress == "" {
		log.Printf("Пустой адрес пира при проверке соединения")
		return false
	}

	log.Printf("Проверка соединения с пиром %s", peerAddress)

	// Формируем простой ping запрос
	pingMessage := Message{
		Type:      "heartbeat",
		Sender:    username,
		Timestamp: time.Now().Unix(),
	}

	// Преобразуем в JSON
	data, err := json.Marshal(pingMessage)
	if err != nil {
		log.Printf("Ошибка при создании ping-сообщения: %v", err)
		return false
	}

	// Пробуем отправить ping с коротким таймаутом
	err = sendTCPDataWithTimeout(peerAddress, tcpPort, data, 1*time.Second)
	if err != nil {
		log.Printf("Пир %s недоступен: %v", peerAddress, err)

		// Обновляем статус пира
		peersMutex.Lock()
		if peer, exists := peers[peerAddress]; exists {
			peer.IsOnline = false
			peers[peerAddress] = peer
		}
		peersMutex.Unlock()

		return false
	}

	// Обновляем статус пира
	peersMutex.Lock()
	if peer, exists := peers[peerAddress]; exists {
		peer.IsOnline = true
		peer.LastSeen = time.Now()
		peers[peerAddress] = peer
	}
	peersMutex.Unlock()

	return true
}

// sendEncryptedMessage шифрует и отправляет сообщение по указанному адресу
func sendEncryptedMessage(peerAddress, content string) error {
	// Добавляем защиту от паники
	defer func() {
		if r := recover(); r != nil {
			log.Printf("КРИТИЧЕСКАЯ ОШИБКА при шифровании/отправке сообщения: %v", r)
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			log.Printf("Стек вызовов: %s", buf[:n])
		}
	}()

	peersMutex.RLock()
	peer, exists := peers[peerAddress]
	peersMutex.RUnlock()

	if !exists {
		return fmt.Errorf("пир не найден")
	}

	// Проверяем наличие публичного ключа
	if peer.PublicKey == nil {
		log.Printf("Публичный ключ пира %s не доступен, запрашиваем", peerAddress)
		sendPublicKeyRequest(peerAddress)
		return fmt.Errorf("публичный ключ пира не доступен, повторите попытку позже")
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
		SessionID: currentSession.SessionID,
	}

	// Сериализуем сообщение
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("ошибка сериализации: %v", err)
	}

	// Отправляем сообщение с увеличенным таймаутом
	err = sendTCPDataWithTimeout(peerAddress, tcpPort, messageJSON, 3*time.Second)
	if err != nil {
		// Обновляем статус пира
		peersMutex.Lock()
		if p, ok := peers[peerAddress]; ok {
			p.IsOnline = false
			peers[peerAddress] = p
		}
		peersMutex.Unlock()

		return fmt.Errorf("ошибка отправки сообщения: %v", err)
	}

	// Обновляем статус пира как онлайн
	peersMutex.Lock()
	if p, ok := peers[peerAddress]; ok {
		p.IsOnline = true
		p.LastSeen = time.Now()
		peers[peerAddress] = p
	}
	peersMutex.Unlock()

	return nil
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
		SessionID: currentSession.SessionID,
	}

	// Сериализуем сообщение
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("ошибка сериализации: %v", err)
	}

	// Отправляем сообщение
	return sendTCPData(peerAddress, tcpPort, messageJSON)
}

// sendPublicKeyRequest отправляет запрос на получение публичного ключа
func sendPublicKeyRequest(peerAddress string) error {
	// Формируем сообщение
	message := Message{
		Type:      "pubkey_request",
		Sender:    username,
		Timestamp: time.Now().Unix(),
		SessionID: currentSession.SessionID,
	}

	// Сериализуем сообщение
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("ошибка сериализации: %v", err)
	}

	// Отправляем сообщение
	return sendTCPData(peerAddress, tcpPort, messageJSON)
}

// sendAuthInfo отправляет информацию аутентификации по указанному адресу
func sendAuthInfo(peerAddress string) error {
	// Формируем сообщение
	message := Message{
		Type:      "auth",
		Sender:    username,
		Timestamp: time.Now().Unix(),
		SessionID: currentSession.SessionID,
	}

	// Сериализуем сообщение
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("ошибка сериализации: %v", err)
	}

	// Отправляем сообщение
	return sendTCPData(peerAddress, tcpPort, messageJSON)
}

// sendNameConflictNotification отправляет уведомление о конфликте имен
func sendNameConflictNotification(peerAddress, conflictingName string) error {
	// Формируем сообщение
	message := Message{
		Type:      "name_conflict",
		Sender:    username,
		Content:   conflictingName,
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
	// Проверяем наличие активного соединения
	connectionsMutex.RLock()
	conn, exists := activeConnections[ip]
	connectionsMutex.RUnlock()

	if exists {
		// Используем существующее соединение
		_, err := conn.Write(data)
		if err != nil {
			// Если ошибка, закрываем соединение и пробуем создать новое
			conn.Close()
			connectionsMutex.Lock()
			delete(activeConnections, ip)
			connectionsMutex.Unlock()
		} else {
			return nil // Успешно отправлено
		}
	}

	// Создаем новое соединение
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return fmt.Errorf("ошибка соединения с %s: %v", addr, err)
	}

	// Сохраняем соединение для будущего использования
	connectionsMutex.Lock()
	activeConnections[ip] = conn
	connectionsMutex.Unlock()

	// Отправляем данные
	_, err = conn.Write(data)
	if err != nil {
		conn.Close()
		connectionsMutex.Lock()
		delete(activeConnections, ip)
		connectionsMutex.Unlock()
		return fmt.Errorf("ошибка отправки данных: %v", err)
	}

	return nil
}

// sendTCPDataWithTimeout отправляет данные по TCP с указанным таймаутом
func sendTCPDataWithTimeout(ip string, port int, data []byte, timeout time.Duration) error {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("ошибка соединения с %s: %v", addr, err)
	}
	defer conn.Close()

	// Устанавливаем таймаут записи
	conn.SetWriteDeadline(time.Now().Add(timeout))

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

// uiAddMessage добавляет новое сообщение в интерфейс
func uiAddMessage(sender, recipient, content string, timestamp int64) {
	// Проверяем инициализацию массива сообщений
	if messages == nil {
		messages = make([]MessageRecord, 0)
	}

	// Проверяем, соответствует ли сообщение текущему выбранному пиру
	if (sender == CurrentPeer && recipient == username) ||
		(sender == username && recipient == CurrentPeer) {
		messages = append(messages, MessageRecord{
			Sender:    sender,
			Recipient: recipient,
			Content:   content,
			Timestamp: timestamp,
		})

		// Обновляем UI в главном потоке
		if messageList != nil {
			MainWindow.Canvas().Refresh(messageList)
			messageList.ScrollToBottom()
		}
	}
}

func handleMessageError(err error, peerAddress string) {
	if err == nil {
		return
	}

	log.Printf("Ошибка обработки сообщения от %s: %v", peerAddress, err)
	GetEventBus().Publish(NetworkEvent{
		Type: EventError,
		Payload: NetworkError{
			Message: fmt.Sprintf("Ошибка обработки сообщения от %s", peerAddress),
			Err:     err,
		},
	})
}
