package main

import (
	"bufio"
	"crypto/rsa"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	keyDir         = "keys"
	privateKeyFile = "private.pem"
	publicKeyFile  = "public.pem"
	tcpPort        = 55556
	// Remove duplicate declaration of discoveryPort - it's already in network.go
	maxMessageSize = 2048
	appVersion     = "0.4.0" // Обновлена версия
)

type Peer struct {
	Address    string
	Name       string
	PublicKey  *rsa.PublicKey
	Connection interface{} // для возможных будущих расширений
}

var (
	privateKey *rsa.PrivateKey
	peers      = make(map[string]Peer)
	peersMutex sync.RWMutex
	username   string
	running    bool
	cmdPrompt  = "> "
	logFile    *os.File
	useUI      bool
)

func main() {
	// Парсим флаги командной строки
	flag.BoolVar(&useUI, "ui", true, "Использовать графический интерфейс")
	flag.Parse()

	// Настройка логирования
	setupLogging()
	defer logFile.Close()

	// Приветствие
	fmt.Printf("SwagNet Messenger v%s (только TCP)\n", appVersion)
	fmt.Println("Безопасный чат для локальной сети")
	fmt.Println("---------------------------------")

	// Получаем имя пользователя
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Введите ваше имя пользователя: ")
	username, _ = reader.ReadString('\n')
	username = strings.TrimSpace(username)

	log.Printf("Запуск с именем пользователя: %s", username)

	// Инициализируем ключи шифрования
	initKeys()

	// Инициализируем базу данных
	if err := initDB(); err != nil {
		log.Printf("Ошибка инициализации базы данных, продолжаем без неё: %v", err)
		dbEnabled = false
	} else {
		// Загружаем известные пиры из базы данных
		loadPeers()
	}

	// Запуск TCP сервера для приема сообщений
	go startTCPServer()

	// Канал для обнаруженных пиров
	discoveredPeers := make(chan Peer)

	// Запускаем TCP сервис обнаружения пиров (заменяет UDP)
	go startDiscoveryTCPServer(discoveredPeers)

	// Отслеживание обнаруженных пиров
	go processPeers(discoveredPeers)

	// Запускаем основной цикл программы
	running = true

	if useUI {
		// Инициализация и запуск графического интерфейса
		initUI()
		runUI()
	} else {
		// Запуск консольного интерфейса
		fmt.Println("SwagNet Messenger запущен (только TCP). Введите /help для помощи.")
		runConsoleUI()
	}

	// Закрываем базу данных при выходе
	if dbEnabled {
		closeDB()
	}

	log.Println("Приложение завершает работу")
}

// setupLogging настраивает логирование
func setupLogging() {
	// Создаем папку для логов
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Ошибка создания директории логов: %v\n", err)
	}

	// Создаем файл лога
	logFilePath := filepath.Join(logDir, fmt.Sprintf("swagnet_%s.log", time.Now().Format("2006-01-02_15-04-05")))
	var err error
	logFile, err = os.Create(logFilePath)
	if err != nil {
		fmt.Printf("Ошибка создания файла лога: %v\n", err)
		return
	}

	// Настраиваем логгер
	log.SetOutput(logFile)
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Println("Логирование инициализировано")
}

// runConsoleUI запускает консольный интерфейс
func runConsoleUI() {
	printPrompt()

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() && running {
		input := scanner.Text()
		handleConsoleInput(input)
		if running {
			printPrompt()
		}
	}
}

// handleConsoleInput обрабатывает ввод пользователя в консольном режиме
func handleConsoleInput(input string) {
	if input == "" {
		return
	}

	log.Printf("Обработка ввода пользователя: %s", input)

	if input[0] == '/' {
		// Обработка команд
		parts := strings.SplitN(input, " ", 2)
		cmd := parts[0]

		switch cmd {
		case "/help":
			showHelp()
		case "/list":
			listPeers()
		case "/msg":
			if len(parts) < 2 {
				fmt.Println("Использование: /msg <имя> <сообщение>")
				log.Println("Неверное использование команды /msg")
				return
			}
			msgParts := strings.SplitN(parts[1], " ", 2)
			if len(msgParts) != 2 {
				fmt.Println("Использование: /msg <имя> <сообщение>")
				log.Println("Неверное использование команды /msg")
				return
			}
			sendMessage(msgParts[0], msgParts[1])
		case "/history":
			if len(parts) < 2 {
				fmt.Println("Использование: /history <имя>")
				log.Println("Неверное использование команды /history")
				return
			}
			showMessageHistory(parts[1])
		case "/scan":
			fmt.Println("Запуск сканирования сети...")
			scanNetwork(getLocalNetworkIPs())
		case "/exit":
			fmt.Println("Завершение работы...")
			log.Println("Пользователь инициировал выход из приложения")
			running = false
		default:
			fmt.Println("Неизвестная команда. Введите /help для помощи.")
			log.Printf("Неизвестная команда: %s", cmd)
		}
	} else {
		// Обычный текст - отправляем всем пирам
		log.Println("Отправка сообщения всем пирам")
		peersMutex.RLock()
		if len(peers) == 0 {
			fmt.Println("Нет доступных пиров для отправки сообщения.")
			log.Println("Попытка отправить сообщение, но пиры не найдены")
		} else {
			for _, peer := range peers {
				sendMessage(peer.Name, input)
			}
		}
		peersMutex.RUnlock()
	}
}

// printPrompt выводит приглашение командной строки
func printPrompt() {
	fmt.Print(cmdPrompt)
}

// showHelp отображает справку
func showHelp() {
	log.Println("Отображение справки")
	fmt.Println("SwagNet Messenger - Доступные команды:")
	fmt.Println("/help - показать эту справку")
	fmt.Println("/list - показать список доступных пиров")
	fmt.Println("/msg <имя> <сообщение> - отправить сообщение указанному пиру")
	fmt.Println("/history <имя> - показать историю сообщений с указанным пиром")
	fmt.Println("/scan - запустить сканирование сети на наличие пиров")
	fmt.Println("/exit - выйти из мессенджера")
	fmt.Println("Просто введите текст для отправки сообщения всем пирам.")
}

// listPeers отображает список пиров
func listPeers() {
	log.Println("Запрос списка пиров")
	peersMutex.RLock()
	defer peersMutex.RUnlock()

	if len(peers) == 0 {
		fmt.Println("Пиров не найдено.")
		log.Println("Список пиров пуст")
		return
	}

	fmt.Println("Доступные пиры:")
	for _, peer := range peers {
		fmt.Printf("- %s (%s)\n", peer.Name, peer.Address)
	}
	log.Printf("Отображено %d пиров", len(peers))
}

// showMessageHistory отображает историю сообщений с указанным пиром
func showMessageHistory(peerName string) {
	if !dbEnabled {
		fmt.Println("История сообщений недоступна: база данных не инициализирована.")
		return
	}

	log.Printf("Запрос истории сообщений с пиром %s", peerName)

	history, err := getMessagesWithPeer(peerName)
	if err != nil {
		fmt.Printf("Ошибка получения истории сообщений: %v\n", err)
		return
	}

	if len(history) == 0 {
		fmt.Println("История сообщений с этим пиром пуста.")
		return
	}

	fmt.Printf("История сообщений с %s:\n", peerName)
	fmt.Println("-----------------------------------")

	for _, msg := range history {
		timestamp := time.Unix(msg.Timestamp, 0).Format("02.01.2006 15:04:05")
		if msg.Sender == username {
			fmt.Printf("[%s] Вы: %s\n", timestamp, msg.Content)
		} else {
			fmt.Printf("[%s] %s: %s\n", timestamp, msg.Sender, msg.Content)
		}
	}

	fmt.Println("-----------------------------------")
	log.Printf("Отображено %d сообщений из истории с пиром %s", len(history), peerName)
}

// fileExists проверяет, существует ли файл
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// processPeers обрабатывает обнаруженных пиров
func processPeers(discoveredPeers <-chan Peer) {
	log.Println("Запуск обработки обнаруженных пиров")
	for peer := range discoveredPeers {
		peersMutex.Lock()
		if _, exists := peers[peer.Address]; !exists {
			log.Printf("Добавление нового пира: %s (%s)", peer.Name, peer.Address)
			peers[peer.Address] = peer

			// Сохраняем пира в базу данных, если она доступна
			if dbEnabled {
				savePeerInfo(peer)
			}

			// Уведомляем UI о новом пире, если UI включен
			if uiEnabled {
				uiUpdatePeerList()
			} else {
				fmt.Printf("\nНайден новый пир: %s (%s)\n", peer.Name, peer.Address)
				printPrompt()
			}
		}
		peersMutex.Unlock()
	}
}
