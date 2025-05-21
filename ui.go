package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

var (
	fyneApp       fyne.App
	mainWindow    fyne.Window
	peerList      *widget.List
	messageList   *widget.List
	messageEntry  *widget.Entry
	scanButton    *widget.Button
	currentPeer   string
	messages      []MessageRecord
	uiEnabled     bool
	lastUIRefresh time.Time
)

// initUI инициализирует графический интерфейс пользователя
func initUI() {
	log.Println("Инициализация пользовательского интерфейса")
	uiEnabled = true

	fyneApp = app.New()
	mainWindow = fyneApp.NewWindow(fmt.Sprintf("SwagNet Messenger v%s (TCP)", appVersion))

	// Инициализация компонентов UI
	initUIComponents()

	// Установка размера окна и флага основного окна
	mainWindow.Resize(fyne.NewSize(800, 600))
	mainWindow.SetMaster()

	// Обработка закрытия окна
	mainWindow.SetOnClosed(func() {
		log.Println("Пользовательский интерфейс закрыт")
		running = false
	})

	log.Println("Пользовательский интерфейс инициализирован")
}

// initUIComponents инициализирует компоненты пользовательского интерфейса
func initUIComponents() {
	// Список пиров с обработчиком выбора
	peerList = widget.NewList(
		func() int {
			peersMutex.RLock()
			defer peersMutex.RUnlock()
			return len(peers)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Имя пира")
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			peersMutex.RLock()
			defer peersMutex.RUnlock()

			var peerNames []string
			for _, peer := range peers {
				peerNames = append(peerNames, peer.Name)
			}

			label := obj.(*widget.Label)
			if id < len(peerNames) {
				label.SetText(peerNames[id])
			}
		},
	)

	// Обработчик выбора пира
	peerList.OnSelected = func(id widget.ListItemID) {
		peersMutex.RLock()
		var peerNames []string
		for _, peer := range peers {
			peerNames = append(peerNames, peer.Name)
		}

		if id < len(peerNames) {
			currentPeer = peerNames[id]
			log.Printf("Выбран пир: %s", currentPeer)
			loadMessagesForCurrentPeer()
		}
		peersMutex.RUnlock()
	}

	// Список сообщений
	messageList = widget.NewList(
		func() int {
			return len(messages)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				widget.NewLabel("Time"),
				widget.NewLabel("Sender:"),
				widget.NewLabel("Message"),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			if id < len(messages) {
				msg := messages[id]
				timestamp := time.Unix(msg.Timestamp, 0).Format("15:04:05")

				timeLabel := obj.(*fyne.Container).Objects[0].(*widget.Label)
				senderLabel := obj.(*fyne.Container).Objects[1].(*widget.Label)
				contentLabel := obj.(*fyne.Container).Objects[2].(*widget.Label)

				timeLabel.SetText(timestamp)

				if msg.Sender == username {
					senderLabel.SetText("Вы:")
				} else {
					senderLabel.SetText(msg.Sender + ":")
				}

				contentLabel.SetText(msg.Content)
			}
		},
	)

	// Поле ввода сообщения
	messageEntry = widget.NewMultiLineEntry()
	messageEntry.SetPlaceHolder("Введите сообщение...")

	// Кнопка отправки сообщения
	sendButton := widget.NewButton("Отправить", sendMessageUI)

	// Кнопка сканирования сети - используем глобальную переменную
	scanButton = widget.NewButton("Сканировать сеть", startNetworkScan)

	// Компоновка интерфейса
	leftPanel := container.NewBorder(
		widget.NewLabel("Доступные пиры:"),
		scanButton,
		nil, nil,
		container.NewVScroll(peerList),
	)

	chatInputContainer := container.NewBorder(
		nil, nil, nil, sendButton,
		messageEntry,
	)

	rightPanel := container.NewBorder(
		widget.NewLabel("Сообщения:"),
		chatInputContainer,
		nil, nil,
		container.NewVScroll(messageList),
	)

	// Создание меню
	mainMenu := fyne.NewMainMenu(
		fyne.NewMenu("Файл",
			fyne.NewMenuItem("О программе", showAboutDialog),
			fyne.NewMenuItem("Выход", func() {
				mainWindow.Close()
			}),
		),
		fyne.NewMenu("Действия",
			fyne.NewMenuItem("Сканировать сеть", startNetworkScan),
			fyne.NewMenuItem("Список пиров", showPeerListDialog),
		),
	)

	mainWindow.SetMainMenu(mainMenu)
	mainWindow.SetContent(container.NewHSplit(leftPanel, rightPanel))
}

// showAboutDialog отображает диалог "О программе"
func showAboutDialog() {
	dialog.ShowInformation(
		"О программе",
		fmt.Sprintf("SwagNet Messenger v%s\nПротокол: TCP\nРазработан как безопасный P2P мессенджер для локальной сети", appVersion),
		mainWindow,
	)
}

// showPeerListDialog отображает диалог со списком пиров
func showPeerListDialog() {
	peersMutex.RLock()
	defer peersMutex.RUnlock()

	var content string
	if len(peers) == 0 {
		content = "Пиры не найдены."
	} else {
		content = "Доступные пиры:\n\n"
		for _, peer := range peers {
			content += fmt.Sprintf("- %s (%s)\n", peer.Name, peer.Address)
		}
	}

	dialog.ShowInformation("Список пиров", content, mainWindow)
}

// sendMessageUI отправляет сообщение из UI
func sendMessageUI() {
	if currentPeer == "" {
		uiShowError("Выберите пира для отправки сообщения.")
		return
	}

	text := messageEntry.Text
	if text == "" {
		return
	}

	// Поиск адреса пира
	var peerAddress string
	peersMutex.RLock()
	for addr, peer := range peers {
		if peer.Name == currentPeer {
			peerAddress = addr
			break
		}
	}
	peersMutex.RUnlock()

	if peerAddress == "" {
		uiShowError("Пир не найден.")
		return
	}

	// Отправка сообщения
	log.Printf("Отправка сообщения пиру %s", currentPeer)
	err := sendEncryptedMessage(peerAddress, text)
	if err != nil {
		log.Printf("Ошибка отправки сообщения: %v", err)
		uiShowError("Ошибка отправки сообщения: " + err.Error())
		return
	}

	// Добавляем сообщение в локальную историю
	timestamp := time.Now().Unix()
	messages = append(messages, MessageRecord{
		Sender:    username,
		Recipient: currentPeer,
		Content:   text,
		Timestamp: timestamp,
	})

	// Обновляем UI
	messageList.Refresh()
	messageList.ScrollToBottom()
	messageEntry.SetText("")

	// Сохраняем сообщение в базу данных
	if dbEnabled {
		saveMessage(username, currentPeer, text, timestamp)
	}
}

// uiShowError отображает сообщение об ошибке
func uiShowError(message string) {
	dialog.ShowError(fmt.Errorf(message), mainWindow)
}

// loadMessagesForCurrentPeer загружает историю сообщений для текущего выбранного пира
func loadMessagesForCurrentPeer() {
	messages = []MessageRecord{}

	if dbEnabled && currentPeer != "" {
		history, err := getMessagesWithPeer(currentPeer)
		if err != nil {
			log.Printf("Ошибка загрузки истории сообщений: %v", err)
			uiShowError("Ошибка загрузки истории сообщений")
		} else {
			messages = history
			log.Printf("Загружено %d сообщений из истории", len(messages))
		}
	}

	messageList.Refresh()
	messageList.ScrollToBottom()
}

// uiUpdatePeerList обновляет список пиров в UI
func uiUpdatePeerList() {
	if !uiEnabled || fyneApp == nil {
		return
	}

	// Предотвращаем слишком частое обновление UI
	now := time.Now()
	if now.Sub(lastUIRefresh) < 500*time.Millisecond {
		return
	}
	lastUIRefresh = now

	log.Println("Обновление списка пиров в UI")

	// Просто обновляем список пиров
	// Не используем mainWindow в качестве CanvasObject
	peerList.Refresh()
}

// uiAddMessage добавляет новое сообщение в интерфейс
func uiAddMessage(sender, recipient, content string, timestamp int64) {
	if !uiEnabled || fyneApp == nil {
		return
	}

	// Проверяем, соответствует ли сообщение текущему выбранному пиру
	if (sender == currentPeer && recipient == username) ||
		(sender == username && recipient == currentPeer) {
		messages = append(messages, MessageRecord{
			Sender:    sender,
			Recipient: recipient,
			Content:   content,
			Timestamp: timestamp,
		})

		messageList.Refresh()
		messageList.ScrollToBottom()
	}
}

// runUI запускает графический интерфейс пользователя
func runUI() {
	log.Println("Запуск интерфейса пользователя")
	mainWindow.ShowAndRun()
	log.Println("Интерфейс пользователя завершен")
}

// startNetworkScan запускает сканирование сети с индикатором прогресса
func startNetworkScan() {
	// Отключаем кнопку сканирования, чтобы избежать повторных нажатий
	scanButton.Disable()

	// Создаем индикатор прогресса
	progress := widget.NewProgressBarInfinite()
	scanStatus := widget.NewLabel("Сканирование сети...")

	// Создаем диалог с индикатором прогресса
	scanDialog := dialog.NewCustom("Сканирование сети", "Отмена",
		container.NewVBox(scanStatus, progress), mainWindow)

	// Канал для отмены сканирования
	cancelScan := make(chan struct{})

	// Обработчик для кнопки "Отмена"
	scanDialog.SetOnClosed(func() {
		close(cancelScan)
	})

	// Показываем диалог
	scanDialog.Show()

	// Запускаем сканирование в отдельной горутине
	go func() {
		// Получаем список IP для сканирования
		ips := getLocalNetworkIPs()

		// Создаем контекст с возможностью отмены
		ctx, cancel := context.WithCancel(context.Background())

		// Горутина для отслеживания канала отмены
		go func() {
			select {
			case <-cancelScan:
				cancel() // Отменяем контекст
			case <-ctx.Done():
				// Сканирование завершено или отменено
			}
		}()

		// Запускаем модифицированную версию сканирования с контекстом
		scanNetworkWithContext(ctx, ips)

		// Закрываем диалог и включаем кнопку снова
		scanDialog.Hide()
		scanButton.Enable()
	}()
}

// scanNetworkWithContext сканирует сеть с поддержкой контекста для отмены
func scanNetworkWithContext(ctx context.Context, ips []string) {
	log.Println("Сканирование сети на наличие пиров")

	// Создаем waitgroup для отслеживания горутин
	var wg sync.WaitGroup

	// Канал для ограничения количества одновременных соединений
	semaphore := make(chan struct{}, 20) // максимум 20 одновременных соединений

	// Сканируем параллельно
	for _, ip := range ips {
		// Проверяем не отменено ли сканирование
		select {
		case <-ctx.Done():
			log.Println("Сканирование отменено пользователем")
			return
		default:
			// Продолжаем сканирование
		}

		// Пропускаем подключение к себе
		if isLocalIP(ip) {
			continue
		}

		// Ожидаем доступного слота в семафоре
		select {
		case semaphore <- struct{}{}:
			// Слот доступен, продолжаем
		case <-ctx.Done():
			// Сканирование отменено
			return
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Освобождаем слот в семафоре

			// Проверяем на отмену перед каждым новым подключением
			select {
			case <-ctx.Done():
				return
			default:
				// Продолжаем
			}

			// Пробуем подключиться по TCP к порту обнаружения с коротким таймаутом
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", discoveryPort))
			conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
			if err != nil {
				// Не логируем - это нормально, что многие IP не ответят
				return
			}

			// Устанавливаем дедлайн для всех операций с соединением
			conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

			// Отправляем запрос обнаружения
			_, err = conn.Write([]byte(discoveryTCPMsg))
			if err != nil {
				conn.Close()
				return
			}

			// Ждем и читаем ответ
			buffer := make([]byte, 2048)
			n, err := conn.Read(buffer)
			conn.Close()

			if err != nil {
				return
			}

			message := string(buffer[:n])
			log.Printf("Получен ответ от %s: %s", addr, message)

			// Обрабатываем ответ как раньше
			if strings.HasPrefix(message, "SWAGNET_PEER|") {
				parts := strings.Split(message, "|")
				if len(parts) == 3 {
					peerName := parts[1]
					pubKeyPEM := parts[2]
					pubKey := parsePublicKeyPEM(pubKeyPEM)

					if pubKey != nil {
						peersMutex.Lock()
						peers[ip] = Peer{
							Address:   ip,
							Name:      peerName,
							PublicKey: pubKey,
						}
						peersMutex.Unlock()

						log.Printf("Добавлен новый пир: %s (%s)", peerName, ip)

						// Уведомляем UI о новом пире
						if uiEnabled {
							uiUpdatePeerList()
						}

						// Сохраняем пира в базу данных
						if dbEnabled {
							savePeerInfo(peers[ip])
						}
					}
				}
			}
		}(ip)
	}

	// Ждем завершения сканирования с возможностью отмены
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Println("Сканирование сети завершено успешно")
	case <-ctx.Done():
		log.Println("Сканирование сети отменено")
	}
}
