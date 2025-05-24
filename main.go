package main

import (
	"bufio"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// --- Константы и глобальные переменные ---

const (
	keyDir            = "keys"
	privateKeyFile    = "private.pem"
	publicKeyFile     = "public.pem"
	tcpPort           = 55556
	maxMessageSize    = 2048
	appVersion        = "0.5.0"          // Обновленная версия с авторизацией
	peerTimeout       = 30 * time.Second // Таймаут для проверки активности пиров
	heartbeatInterval = 10 * time.Second // Интервал отправки heartbeat
)

type Peer struct {
	Address    string
	Name       string
	PublicKey  *rsa.PublicKey
	Connection interface{}
	LastSeen   time.Time // Время последней активности
	IsOnline   bool      // Статус онлайн
}

var (
	privateKey        *rsa.PrivateKey
	peers             = make(map[string]Peer)
	peersMutex        sync.RWMutex
	username          string
	running           bool
	cmdPrompt         = "> "
	logLevelFlag      string
	useUI             bool
	isReconnect       bool // флаг для отслеживания переподключения
	uiEnabled         bool
	tcpListener       net.Listener
	discoveryListener net.Listener
	networkMutex      sync.Mutex
)

// --- Функция аутентификации пользователя ---
func authenticateUser() error {
	if err := initAuth(); err != nil {
		return fmt.Errorf("ошибка инициализации системы авторизации: %v", err)
	}

	reader := bufio.NewReader(os.Stdin)

	// Проверяем наличие сохраненной сессии
	if session, err := loadSession(); err == nil && validateSession() {
		// Загружаем профиль пользователя
		if user, err := loadUserProfile(session.Username); err == nil {
			username = user.Username
			fmt.Printf("Добро пожаловать обратно, %s!\n", username)
			return nil
		}
		// Если не удалось загрузить профиль, очищаем сессию
		clearSession()
	}

	// Интерактивная авторизация
	for {
		fmt.Println("\n=== SwagNet Messenger - Авторизация ===")
		fmt.Println("1. Войти")
		fmt.Println("2. Зарегистрироваться")
		fmt.Println("3. Список пользователей")
		fmt.Println("4. Выход")
		fmt.Print("Выберите действие (1-4): ")

		choice, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("ошибка чтения ввода: %v", err)
		}
		choice = strings.TrimSpace(choice)

		switch choice {
		case "1":
			if err := handleLogin(reader); err != nil {
				fmt.Printf("Ошибка входа: %v\n", err)
				continue
			}
			return nil

		case "2":
			if err := handleRegistration(reader); err != nil {
				fmt.Printf("Ошибка регистрации: %v\n", err)
				continue
			}
			fmt.Println("Регистрация успешна! Теперь войдите в систему.")

		case "3":
			if err := handleListUsers(); err != nil {
				fmt.Printf("Ошибка получения списка пользователей: %v\n", err)
			}

		case "4":
			return fmt.Errorf("выход из программы")

		default:
			fmt.Println("Неверный выбор. Попробуйте еще раз.")
		}
	}
}

// handleLogin обрабатывает процесс входа
func handleLogin(reader *bufio.Reader) error {
	fmt.Print("Имя пользователя: ")
	usernameInput, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	usernameInput = strings.TrimSpace(usernameInput)

	fmt.Print("Пароль: ")
	passwordInput, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	passwordInput = strings.TrimSpace(passwordInput)

	if err := loginUser(usernameInput, passwordInput); err != nil {
		return err
	}

	username = usernameInput
	fmt.Printf("Добро пожаловать, %s!\n", username)
	return nil
}

// handleRegistration обрабатывает процесс регистрации
func handleRegistration(reader *bufio.Reader) error {
	fmt.Print("Имя пользователя (минимум 3 символа): ")
	usernameInput, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	usernameInput = strings.TrimSpace(usernameInput)

	// Проверяем существование пользователя
	if checkUserExists(usernameInput) {
		return fmt.Errorf("пользователь с таким именем уже существует")
	}

	fmt.Print("Пароль (минимум 6 символов): ")
	passwordInput, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	passwordInput = strings.TrimSpace(passwordInput)

	fmt.Print("Подтвердите пароль: ")
	confirmInput, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	confirmInput = strings.TrimSpace(confirmInput)

	if passwordInput != confirmInput {
		return fmt.Errorf("пароли не совпадают")
	}

	return registerUser(usernameInput, passwordInput)
}

// handleListUsers показывает список зарегистрированных пользователей
func handleListUsers() error {
	users, err := listUsers()
	if err != nil {
		return err
	}

	if len(users) == 0 {
		fmt.Println("Зарегистрированных пользователей нет.")
		return nil
	}

	fmt.Println("\nЗарегистрированные пользователи:")
	for i, user := range users {
		fmt.Printf("%d. %s\n", i+1, user)
	}
	return nil
}

// cleanupNetworkResources корректно закрывает все сетевые ресурсы
func cleanupNetworkResources() {
	networkMutex.Lock()
	defer networkMutex.Unlock()

	if tcpListener != nil {
		LogInfo("Закрытие TCP сервера сообщений")
		tcpListener.Close()
		tcpListener = nil
	}

	if discoveryListener != nil {
		LogInfo("Закрытие TCP сервера обнаружения")
		discoveryListener.Close()
		discoveryListener = nil
	}

	time.Sleep(500 * time.Millisecond) // Даем время на закрытие соединений
}

// --- Улучшенная функция runSession ---
func runSession() {
	// Флаг для отслеживания попыток повторного входа
	isReconnecting := isReconnect

	// Очищаем сетевые ресурсы перед запуском новой сессии
	cleanupNetworkResources()

	// Аутентификация пользователя
	if err := authenticateUser(); err != nil {
		if err.Error() != "выход из программы" {
			LogError("Ошибка аутентификации: %v", err)
			fmt.Printf("Ошибка аутентификации: %v\n", err)
		}
		return
	}

	// Устанавливаем флаг работы сессии
	running = true

	// Инициализация ключей шифрования
	initKeys()

	// Инициализация базы данных
	if err := initDB(); err != nil {
		LogInfo("Ошибка инициализации базы данных, продолжаем без неё: %v", err)
		dbEnabled = false
	} else {
		// Загружаем известных пиров из БД
		loadPeers()
	}

	// Очищаем старые пиры при переподключении
	if isReconnecting {
		peersMutex.Lock()
		// Помечаем всех пиров как оффлайн
		for addr, peer := range peers {
			peer.IsOnline = false
			peer.LastSeen = time.Now().Add(-peerTimeout)
			peers[addr] = peer
		}
		peersMutex.Unlock()
	}

	// Запускаем фоновые сервисы, но с защитой от паники
	serverStartErrors := 0

	// Канал для сообщений от обнаруженных пиров
	discoveredPeers := make(chan Peer)

	// Запускаем обработчик пиров сразу
	go processPeers(discoveredPeers)

	// Запускаем службу обнаружения
	startDiscoveryTCPServer(discoveredPeers)

	// Запускаем TCP сервер для сообщений
	startTCPServer()

	// Запускаем сервис отслеживания активности пиров
	go startHeartbeatService()

	// Проверяем состояние сетевых сервисов
	networkMutex.Lock()
	tcpListenerActive := tcpListener != nil
	discoveryListenerActive := discoveryListener != nil
	networkMutex.Unlock()

	if !tcpListenerActive || !discoveryListenerActive {
		serverStartErrors++
		LogWarn("ПРЕДУПРЕЖДЕНИЕ: Проблемы с сетевыми сервисами: TCP=%v, Discovery=%v",
			tcpListenerActive, discoveryListenerActive)
	}

	// Проверяем ошибки запуска серверов
	if serverStartErrors > 0 {
		LogWarn("ПРЕДУПРЕЖДЕНИЕ: Возникли ошибки при запуске серверов (%d)", serverStartErrors)
		fmt.Printf("\nПРЕДУПРЕЖДЕНИЕ: Возникли ошибки при запуске серверов. Приложение может работать нестабильно.\n")
	}

	// Проверяем еще раз текущий режим работы
	currentUIMode := useUI

	// Запуск пользовательского интерфейса
	if currentUIMode {
		LogInfo("Запуск приложения в режиме UI (useUI=%v, uiEnabled=%v)", useUI, uiEnabled)

		// Инициализируем UI с защитой от паник
		initUI()

		// Проверяем, было ли UI успешно инициализировано
		if !uiEnabled || FyneApp == nil || MainWindow == nil {
			LogInfo("UI не был инициализирован успешно, переключаемся на консольный режим")
			fmt.Println("Не удалось запустить графический интерфейс. Запускаем консольный режим.")
			useUI = false
			uiEnabled = false
			fmt.Printf("SwagNet Messenger запущен. Пользователь: %s\n", username)
			fmt.Println("Введите /help для помощи.")
			runConsoleUI()
		} else {
			// Запускаем UI напрямую из основной горутины, так как FyneApp.Run()
			// должен вызываться только из основного потока
			runUI()
		}
	} else {
		fmt.Printf("SwagNet Messenger запущен. Пользователь: %s\n", username)
		fmt.Println("Введите /help для помощи.")
		runConsoleUI()
	}

	// Завершение сессии
	LogInfo("Завершение сессии")
	if dbEnabled {
		closeDB()
	}

	// Очищаем сетевые ресурсы перед выходом, чтобы гарантировать их освобождение
	cleanupNetworkResources()

	// Помечаем сессию как завершенную
	running = false

	// Явно очищаем сессию при выходе
	clearSession()

	LogInfo("Сессия завершена, ресурсы освобождены.")
}

// startHeartbeatService запускает сервис отслеживания активности пиров
func startHeartbeatService() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	for running {
		<-ticker.C
		cleanupInactivePeers()
		sendHeartbeatToPeers()
	}
}

// cleanupInactivePeers удаляет неактивных пиров
func cleanupInactivePeers() {
	peersMutex.Lock()
	defer peersMutex.Unlock()

	now := time.Now()
	var toDelete []string

	for addr, peer := range peers {
		if now.Sub(peer.LastSeen) > peerTimeout {
			if peer.IsOnline {
				LogInfo("Пир %s (%s) стал неактивным", peer.Name, addr)
				peer.IsOnline = false
				peers[addr] = peer
			}

			// Удаляем совсем старые записи (более 5 минут неактивности)
			if now.Sub(peer.LastSeen) > 5*time.Minute {
				toDelete = append(toDelete, addr)
			}
		}
	}

	// Удаляем старые записи
	for _, addr := range toDelete {
		LogInfo("Удаляем неактивного пира: %s", addr)
		delete(peers, addr)
	}

	// Обновляем UI если есть изменения
	if len(toDelete) > 0 && uiEnabled {
		// Безопасное обновление UI через внешнюю функцию
		safeUpdateUI()
	}
}

// sendHeartbeatToPeers отправляет heartbeat активным пирам
func sendHeartbeatToPeers() {
	peersMutex.RLock()
	activePeers := make([]string, 0)
	for addr, peer := range peers {
		if peer.IsOnline {
			activePeers = append(activePeers, addr)
		}
	}
	peersMutex.RUnlock()

	// Отправляем heartbeat каждому активному пиру
	for _, addr := range activePeers {
		go sendHeartbeat(addr)
	}
}

// sendHeartbeat отправляет heartbeat конкретному пиру
func sendHeartbeat(peerAddress string) {
	heartbeat := map[string]interface{}{
		"type":      "heartbeat",
		"sender":    username,
		"timestamp": time.Now().Unix(),
	}

	data, err := json.Marshal(heartbeat)
	if err != nil {
		LogError("Ошибка сериализации heartbeat: %v", err)
		return
	}

	// Отправляем с коротким таймаутом
	if err := sendTCPDataWithTimeout(peerAddress, tcpPort, data, 2*time.Second); err != nil {
		LogError("Не удалось отправить heartbeat пиру %s: %v", peerAddress, err)

		// Помечаем пира как неактивного
		peersMutex.Lock()
		if peer, exists := peers[peerAddress]; exists {
			peer.IsOnline = false
			peers[peerAddress] = peer
		}
		peersMutex.Unlock()
	}
}

// updatePeerActivity обновляет время последней активности пира
func updatePeerActivity(peerAddress string) {
	peersMutex.Lock()
	defer peersMutex.Unlock()

	if peer, exists := peers[peerAddress]; exists {
		peer.LastSeen = time.Now()
		peer.IsOnline = true
		peers[peerAddress] = peer
	}
}

// --- Главная функция main ---
func main() {
	// Обработка паник на верхнем уровне
	defer func() {
		if r := recover(); r != nil {
			// Записываем информацию о панике в лог
			buf := make([]byte, 8192)
			n := runtime.Stack(buf, false)
			errorMsg := fmt.Sprintf("КРИТИЧЕСКАЯ ОШИБКА: Необработанная паника в приложении: %v\n%s",
				r, buf[:n])

			// Выводим в консоль
			fmt.Printf("\n%s\n", errorMsg)

			// Записываем в лог, если логирование доступно
			LogError("%s", errorMsg)

			// Даем пользователю возможность увидеть сообщение перед выходом
			fmt.Println("\nПриложение аварийно завершило работу. Нажмите Enter для выхода...")
			bufio.NewReader(os.Stdin).ReadBytes('\n')
			os.Exit(1)
		}
	}()

	// Парсим флаги командной строки
	flag.StringVar(&logLevelFlag, "log-level", "info", "Уровень логирования: debug, info, warn, error")
	flag.BoolVar(&useUI, "ui", true, "Использовать графический интерфейс")
	flag.Parse()

	setLogLevel(logLevelFlag)

	// Инициализация UI флага - всегда включен, если не указано иное
	if !flag.Parsed() {
		useUI = true
	}
	uiEnabled = useUI

	fmt.Printf("Графический интерфейс: %v\n", useUI)

	if err := setupLogging(); err != nil {
		fmt.Printf("Ошибка настройки логирования: %v\n", err)
		fmt.Println("Продолжаем работу без логирования...")
	}

	// Устанавливаем флаг работы приложения
	running = true

	// Приветственное сообщение
	LogInfo("SwagNet Messenger v%s", appVersion)
	fmt.Println("Безопасный P2P чат для локальной сети")
	fmt.Println("=====================================")

	// Запускаем одну сессию и завершаем работу приложения
	runSession()

	LogInfo("Приложение завершает работу")
}
