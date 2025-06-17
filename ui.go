package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// MessageKey используется для идентификации уникальных сообщений
type MessageKey struct {
	Sender    string
	Timestamp int64
	Content   string
}

var (
	// Переменные UI
	FyneApp      fyne.App
	MainWindow   fyne.Window
	peerList     *widget.List
	messageList  *widget.List
	messageEntry *widget.Entry
	scanButton   *widget.Button
	CurrentPeer  string
	messages     []MessageRecord
	uiMutex      sync.Mutex
	uiActive     bool
	debugMode    bool // Режим отладки

	// Добавляем новые переменные для управления обновлениями
	messageUpdateTicker *time.Ticker
	peerUpdateTicker    *time.Ticker

	// Добавляем переменную для отслеживания последнего обновления сообщений
	lastMessageTimestamp int64

	// Добавляем map для отслеживания уникальных сообщений
	processedMessages = make(map[MessageKey]bool)
	messagesMutex     sync.RWMutex
)

// PeerListItem представляет элемент списка пиров с индикатором статуса
type PeerListItem struct {
	widget.BaseWidget
	peer     Peer
	selected bool
}

// PeerListItemRenderer is the renderer for PeerListItem
type PeerListItemRenderer struct {
	item          *PeerListItem
	statusColor   *canvas.Circle
	nameLabel     *widget.Label
	lastSeenLabel *widget.Label
	unreadLabel   *widget.Label
	objects       []fyne.CanvasObject
}

func (r *PeerListItemRenderer) Destroy() {}

func (r *PeerListItemRenderer) Layout(size fyne.Size) {
	r.statusColor.Resize(fyne.NewSize(10, 10))
	r.statusColor.Move(fyne.NewPos(5, (size.Height-10)/2))

	nameSize := r.nameLabel.MinSize()
	r.nameLabel.Resize(nameSize)
	r.nameLabel.Move(fyne.NewPos(20, (size.Height-nameSize.Height)/2))

	unreadSize := r.unreadLabel.MinSize()
	r.unreadLabel.Resize(unreadSize)
	r.unreadLabel.Move(fyne.NewPos(25+nameSize.Width, (size.Height-unreadSize.Height)/2))

	lastSeenSize := r.lastSeenLabel.MinSize()
	r.lastSeenLabel.Resize(lastSeenSize)
	r.lastSeenLabel.Move(fyne.NewPos(size.Width-lastSeenSize.Width-5, (size.Height-lastSeenSize.Height)/2))
}

func (r *PeerListItemRenderer) MinSize() fyne.Size {
	nameSize := r.nameLabel.MinSize()
	unreadSize := r.unreadLabel.MinSize()
	lastSeenSize := r.lastSeenLabel.MinSize()

	width := 20 + nameSize.Width + unreadSize.Width + lastSeenSize.Width + 10
	height := fyne.Max(fyne.Max(nameSize.Height, unreadSize.Height), lastSeenSize.Height)

	return fyne.NewSize(width, height+10)
}

func (r *PeerListItemRenderer) Objects() []fyne.CanvasObject {
	return r.objects
}

func (r *PeerListItemRenderer) Refresh() {
	if r.item.peer.IsOnline {
		r.statusColor.FillColor = theme.SuccessColor()
	} else {
		r.statusColor.FillColor = theme.DisabledColor()
	}
	r.statusColor.Refresh()

	r.nameLabel.SetText(r.item.peer.Name)
	r.nameLabel.Refresh()

	r.lastSeenLabel.SetText(formatLastSeen(r.item.peer.LastSeen))
	r.lastSeenLabel.Refresh()

	// Получаем количество непрочитанных сообщений
	unreadCount := 0
	if messages, err := getMessagesWithPeer(r.item.peer.Name); err == nil {
		for _, msg := range messages {
			if !msg.IsRead && msg.Sender == r.item.peer.Name {
				unreadCount++
			}
		}
	}

	if unreadCount > 0 {
		r.unreadLabel.SetText(fmt.Sprintf("(%d)", unreadCount))
	} else {
		r.unreadLabel.SetText("")
	}
	r.unreadLabel.Refresh()
}

func (p *PeerListItem) CreateRenderer() fyne.WidgetRenderer {
	statusColor := canvas.NewCircle(theme.DisabledColor())
	if p.peer.IsOnline {
		statusColor.FillColor = theme.SuccessColor()
	}
	statusColor.Resize(fyne.NewSize(10, 10))

	nameLabel := widget.NewLabel(p.peer.Name)
	nameLabel.TextStyle = fyne.TextStyle{Bold: true}

	lastSeenLabel := widget.NewLabel(formatLastSeen(p.peer.LastSeen))
	lastSeenLabel.TextStyle = fyne.TextStyle{Monospace: true}

	unreadLabel := widget.NewLabel("")
	unreadLabel.TextStyle = fyne.TextStyle{Bold: true}

	renderer := &PeerListItemRenderer{
		item:          p,
		statusColor:   statusColor,
		nameLabel:     nameLabel,
		lastSeenLabel: lastSeenLabel,
		unreadLabel:   unreadLabel,
		objects:       []fyne.CanvasObject{statusColor, nameLabel, unreadLabel, lastSeenLabel},
	}

	return renderer
}

// formatLastSeen форматирует время последнего онлайна
func formatLastSeen(t time.Time) string {
	if t.IsZero() {
		return ""
	}

	duration := time.Since(t)
	switch {
	case duration < time.Minute:
		return "только что"
	case duration < time.Hour:
		return fmt.Sprintf("%d мин назад", int(duration.Minutes()))
	case duration < 24*time.Hour:
		return fmt.Sprintf("%d ч назад", int(duration.Hours()))
	default:
		return t.Format("02.01 15:04")
	}
}

// enableUIDebugMode включает расширенное логирование для отладки UI
func enableUIDebugMode() {
	debugMode = true
	LogDebug("Включен режим отладки UI")

	// Перехватываем паники в UI потоках
	fyne.CurrentApp().Lifecycle().SetOnStarted(func() {
		LogDebug("DEBUG: UI поток запущен")
	})

	fyne.CurrentApp().Lifecycle().SetOnStopped(func() {
		LogDebug("DEBUG: UI поток остановлен")
	})
}

// initUI инициализирует графический интерфейс пользователя
func initUI() {
	LogInfo("Инициализация пользовательского интерфейса")

	// Защита от паники при инициализации UI
	defer func() {
		if r := recover(); r != nil {
			LogError("КРИТИЧЕСКАЯ ОШИБКА при инициализации UI: %v", r)
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			LogDebug("Стек вызовов: %s", buf[:n])

			// Помечаем, что UI не активен
			uiMutex.Lock()
			uiActive = false
			uiMutex.Unlock()

			// Отключаем флаг UI
			uiEnabled = false
			useUI = false
		}
	}()

	// Включение режима отладки
	debugMode = true

	// Создаем приложение и окно в защищенном блоке
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				LogError("Паника при создании приложения: %v", r)
				err = fmt.Errorf("ошибка создания приложения: %v", r)
			}
		}()

		uiMutex.Lock()
		uiActive = true
		FyneApp = app.New()
		MainWindow = FyneApp.NewWindow(fmt.Sprintf("SwagNet Messenger v%s (TCP)", appVersion))
		uiMutex.Unlock()
	}()

	// Проверяем результат создания
	if err != nil || FyneApp == nil || MainWindow == nil {
		LogError("ОШИБКА: Не удалось создать приложение Fyne")
		uiMutex.Lock()
		uiActive = false
		uiMutex.Unlock()
		uiEnabled = false
		useUI = false
		return
	}

	if debugMode {
		enableUIDebugMode()
		LogDebug("DEBUG: Создан экземпляр приложения и основного окна")
	}

	// Инициализация компонентов UI с защитой от паник
	err = func() error {
		defer func() {
			if r := recover(); r != nil {
				LogError("Паника при инициализации компонентов: %v", r)
				err = fmt.Errorf("ошибка инициализации компонентов: %v", r)
			}
		}()

		initUIComponents()

		// Создаем левую панель с кнопкой сканирования и списком пиров
		leftPanel := container.NewVBox(
			scanButton,
			widget.NewLabel("Список пиров:"),
			peerList,
		)

		// Создаем правую панель
		rightPanel := container.NewBorder(
			container.NewVBox(
				widget.NewLabelWithStyle("Чат", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
			),
			container.NewPadded(
				container.NewBorder(
					widget.NewSeparator(),
					nil,
					nil,
					widget.NewButtonWithIcon("Отправить", theme.MailSendIcon(), sendMessageUI),
					container.NewPadded(messageEntry),
				),
			),
			nil,
			nil,
			container.NewPadded(messageList),
		)

		// Создаем разделенный контейнер
		split := container.NewHSplit(leftPanel, rightPanel)
		split.SetOffset(0.25) // 25% для списка пиров

		MainWindow.SetContent(split)

		// Подписываемся на события сети
		subscribeToNetworkEvents()

		// Создаем меню
		mainMenu := fyne.NewMainMenu(
			fyne.NewMenu("Файл",
				fyne.NewMenuItem("О программе", showAboutDialog),
				fyne.NewMenuItem("Список пиров", showPeerListDialog),
				fyne.NewMenuItem("Выход", func() {
					cleanup()
					MainWindow.Close()
				}),
			),
		)
		MainWindow.SetMainMenu(mainMenu)

		return nil
	}()

	if err != nil {
		LogError("ОШИБКА: %v", err)
		uiMutex.Lock()
		uiActive = false
		uiMutex.Unlock()
		uiEnabled = false
		useUI = false
		return
	}

	// Установка размера окна и флага основного окна
	MainWindow.Resize(fyne.NewSize(800, 600))
	MainWindow.SetMaster()

	// Обработка закрытия окна
	MainWindow.SetOnClosed(func() {
		LogInfo("Пользовательский интерфейс закрыт")
		cleanup()
		uiMutex.Lock()
		uiActive = false
		uiMutex.Unlock()
		running = false

		// Завершаем приложение
		os.Exit(0)
	})

	LogInfo("Пользовательский интерфейс инициализирован")
}

// initUIComponents инициализирует компоненты пользовательского интерфейса
func initUIComponents() {
	// Инициализируем список пиров с новым виджетом
	peerList = widget.NewList(
		func() int {
			peersMutex.Lock()
			defer peersMutex.Unlock()
			return len(peers)
		},
		func() fyne.CanvasObject {
			return NewPeerListItem(Peer{})
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			fyne.Do(func() {
				peersMutex.Lock()
				defer peersMutex.Unlock()

				item := obj.(*PeerListItem)
				i := 0
				for _, peer := range peers {
					if i == id {
						item.peer = peer
						item.Refresh()
						break
					}
					i++
				}
			})
		},
	)

	// Обработчик выбора пира
	peerList.OnSelected = func(id widget.ListItemID) {
		fyne.Do(func() {
			peersMutex.RLock()
			var peerNames []string
			for _, peer := range peers {
				peerNames = append(peerNames, peer.Name)
			}
			peersMutex.RUnlock()

			if id < len(peerNames) {
				CurrentPeer = peerNames[id]
				loadMessagesForCurrentPeer()
			}
		})
	}

	// Список сообщений
	messageList = widget.NewList(
		func() int {
			return len(messages)
		},
		func() fyne.CanvasObject {
			timeLabel := widget.NewLabel("00:00:00")
			timeLabel.TextStyle = fyne.TextStyle{Monospace: true}
			timeLabel.Resize(fyne.NewSize(80, timeLabel.MinSize().Height))

			userLabel := widget.NewLabel("User")
			userLabel.TextStyle = fyne.TextStyle{Bold: true}
			userLabel.Resize(fyne.NewSize(100, userLabel.MinSize().Height))

			messageLabel := widget.NewLabel("Message content")

			return container.NewHBox(
				timeLabel,
				widget.NewLabel(" "), // Разделитель
				userLabel,
				widget.NewLabel(" "), // Разделитель
				messageLabel,
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			box := obj.(*fyne.Container)
			timeLabel := box.Objects[0].(*widget.Label)
			userLabel := box.Objects[2].(*widget.Label)
			messageLabel := box.Objects[4].(*widget.Label)

			if id < len(messages) {
				msg := messages[id]
				timestamp := time.Unix(msg.Timestamp, 0).Format("15:04:05")
				timeLabel.SetText(timestamp)

				if msg.Sender == username {
					userLabel.SetText("Вы:")
				} else {
					userLabel.SetText(msg.Sender + ":")
				}

				messageLabel.SetText(msg.Content)
			}
		},
	)
	messageList.OnSelected = func(id widget.ListItemID) {
		messageList.Unselect(id) // Отключаем выделение сообщений
	}

	// Поле ввода сообщения с поддержкой Enter
	messageEntry = widget.NewMultiLineEntry()
	messageEntry.SetPlaceHolder("Введите сообщение...")
	messageEntry.Wrapping = fyne.TextWrapWord

	// Создаем кастомный обработчик для Enter
	messageEntry.OnChanged = func(text string) {
		// Проверяем, заканчивается ли текст на перевод строки
		if len(text) > 0 && text[len(text)-1] == '\n' {
			// Удаляем символ новой строки
			messageEntry.SetText(text[:len(text)-1])
			// Отправляем сообщение если оно не пустое
			if messageEntry.Text != "" {
				sendMessageUI()
			}
		}
	}

	messageEntry.Resize(fyne.NewSize(300, 60))

	// Кнопка сканирования сети
	scanButton = widget.NewButtonWithIcon("Сканировать", theme.SearchIcon(), func() {
		if debugMode {
			LogDebug("DEBUG: Нажата кнопка сканирования сети")
		}
		startManualScan()
	})

	// Создаем левую панель
	leftPanel := container.NewBorder(
		container.NewVBox(
			container.NewHBox(
				scanButton,
				widget.NewButtonWithIcon("", theme.ViewRefreshIcon(), func() {
					MainWindow.Canvas().Refresh(peerList)
				}),
			),
		),
		nil,
		nil,
		nil,
		container.NewVBox(
			widget.NewLabelWithStyle("Список пиров", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewSeparator(),
			peerList,
		),
	)

	// Создаем правую панель
	rightPanel := container.NewBorder(
		container.NewVBox(
			widget.NewLabelWithStyle("Чат", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			widget.NewSeparator(),
		),
		container.NewPadded(
			container.NewBorder(
				widget.NewSeparator(),
				nil,
				nil,
				widget.NewButtonWithIcon("Отправить", theme.MailSendIcon(), sendMessageUI),
				container.NewPadded(messageEntry),
			),
		),
		nil,
		nil,
		container.NewPadded(messageList),
	)

	// Создаем разделенный контейнер
	split := container.NewHSplit(leftPanel, rightPanel)
	split.SetOffset(0.25) // 25% для списка пиров

	MainWindow.SetContent(split)

	// Запускаем периодическое обновление UI и обработку сообщений
	startPeriodicUpdates()
}

// showAboutDialog отображает диалог "О программе"
func showAboutDialog() {
	fyne.Do(func() {
		dialog.ShowInformation(
			"О программе",
			fmt.Sprintf("SwagNet Messenger v%s\nПротокол: TCP\nРазработан как безопасный P2P мессенджер для локальной сети", appVersion),
			MainWindow,
		)
	})
}

// showPeerListDialog отображает диалог со списком пиров
func showPeerListDialog() {
	peersMutex.Lock()
	peerCount := len(peers)
	peerInfo := make([]Peer, 0, peerCount)
	for _, peer := range peers {
		peerInfo = append(peerInfo, peer)
	}
	peersMutex.Unlock()

	content := container.NewVBox()

	for _, peer := range peerInfo {
		// Создаем контейнер для информации о пире
		peerBox := container.NewVBox()

		// Статус и имя
		statusRow := container.NewHBox()
		status := canvas.NewCircle(theme.DisabledColor())
		if peer.IsOnline {
			status.FillColor = theme.SuccessColor()
		}
		status.Resize(fyne.NewSize(10, 10))
		statusRow.Add(status)
		statusRow.Add(widget.NewLabel("  " + peer.Name))
		peerBox.Add(statusRow)

		// Детальная информация
		details := container.NewVBox(
			widget.NewLabel(fmt.Sprintf("Адрес: %s", peer.Address)),
			widget.NewLabel(fmt.Sprintf("Последняя активность: %s", formatLastSeen(peer.LastSeen))),
		)

		// Добавляем статистику сообщений
		if messages, err := getMessagesWithPeer(peer.Name); err == nil {
			var unread int
			for _, msg := range messages {
				if !msg.IsRead && msg.Sender == peer.Name {
					unread++
				}
			}
			details.Add(widget.NewLabel(fmt.Sprintf("Всего сообщений: %d", len(messages))))
			details.Add(widget.NewLabel(fmt.Sprintf("Непрочитанных: %d", unread)))
		}

		peerBox.Add(details)
		peerBox.Add(widget.NewSeparator())
		content.Add(peerBox)
	}

	dialog.ShowCustom("Информация о пирах", "Закрыть",
		container.NewScroll(content),
		MainWindow)
}

// Функция для проверки дубликатов сообщений
func isMessageDuplicate(msg MessageRecord) bool {
	key := MessageKey{
		Sender:    msg.Sender,
		Timestamp: msg.Timestamp,
		Content:   msg.Content,
	}

	messagesMutex.Lock()
	defer messagesMutex.Unlock()

	if processedMessages[key] {
		return true
	}

	processedMessages[key] = true
	return false
}

// Обновляем функцию добавления сообщения
func addMessage(msg MessageRecord) {
	if isMessageDuplicate(msg) {
		return
	}

	messagesMutex.Lock()
	messages = append(messages, msg)
	messagesMutex.Unlock()

	// Обновляем UI только если это сообщение для текущего чата
	if msg.Sender == CurrentPeer || msg.Recipient == CurrentPeer {
		fyne.Do(func() {
			if messageList != nil {
				messageList.Refresh()
				messageList.ScrollToBottom()
			}
		})
	}
}

// Обновляем функцию загрузки сообщений
func loadMessagesForCurrentPeer() {
	if CurrentPeer == "" {
		return
	}

	// Загружаем сообщения
	var err error
	messages, err = getMessagesWithPeer(CurrentPeer)
	if err != nil {
		LogError("Ошибка загрузки сообщений: %v", err)
		return
	}

	// Помечаем сообщения как прочитанные
	for _, msg := range messages {
		if !msg.IsRead && msg.Sender == CurrentPeer {
			if err := dbManager.MarkMessageAsRead(msg.ID); err != nil {
				LogError("Ошибка пометки сообщения как прочитанного: %v", err)
			}
		}
	}

	// Обновляем UI
	if messageList != nil {
		messageList.Refresh()
	}
	if peerList != nil {
		peerList.Refresh()
	}
}

// startPeriodicUpdates запускает периодическое обновление UI
func startPeriodicUpdates() {
	// Обновление списка сообщений каждую секунду вместо 500мс
	messageUpdateTicker = time.NewTicker(1 * time.Second)
	go func() {
		for range messageUpdateTicker.C {
			if CurrentPeer != "" {
				fyne.Do(func() {
					loadMessagesForCurrentPeer()
				})
			}
		}
	}()

	// Обновление списка пиров каждые 2 секунды
	peerUpdateTicker = time.NewTicker(2 * time.Second)
	go func() {
		for range peerUpdateTicker.C {
			fyne.Do(func() {
				MainWindow.Canvas().Refresh(peerList)
			})
		}
	}()

	// Подписываемся на события новых сообщений
	GetEventBus().Subscribe(func(event NetworkEvent) {
		switch event.Type {
		case EventMessageReceived:
			if msg, ok := event.Payload.(MessageRecord); ok {
				fyne.Do(func() {
					addMessage(msg)
				})
			}
		}
	})
}

// Обновляем обработчик событий сети
func subscribeToNetworkEvents() {
	GetEventBus().Subscribe(func(event NetworkEvent) {
		switch event.Type {
		case EventPeerDiscovered:
			// Обновляем UI
			fyne.Do(func() {
				MainWindow.Canvas().Refresh(peerList)
			})

		case EventScanStarted:
			// Обновляем состояние кнопки сканирования
			fyne.Do(func() {
				scanButton.Disable()
				scanButton.SetText("Сканирование...")
			})

		case EventScanFinished:
			// Восстанавливаем состояние кнопки
			fyne.Do(func() {
				scanButton.Enable()
				scanButton.SetText("Сканировать сеть")
				MainWindow.Canvas().Refresh(peerList)
			})
		}
	})
}

// Обновляем функцию закрытия окна
func cleanup() {
	if messageUpdateTicker != nil {
		messageUpdateTicker.Stop()
	}
	if peerUpdateTicker != nil {
		peerUpdateTicker.Stop()
	}
	LogInfo("Периодические обновления UI остановлены")
}

// runUI запускает пользовательский интерфейс
func runUI() {
	// Инициализируем UI
	initUI()

	// Запускаем главный цикл приложения
	MainWindow.ShowAndRun()
}

// safeUpdateUI безопасно обновляет UI из любой части приложения
func safeUpdateUI() {
	fyne.Do(func() {
		if peerList != nil {
			MainWindow.Canvas().Refresh(peerList)
		}
	})
}

// getNewMessages получает новые сообщения с определенным пиром после указанного timestamp
func getNewMessages(peer string, since int64) ([]MessageRecord, error) {
	if dbManager == nil {
		return nil, fmt.Errorf("менеджер базы данных не инициализирован")
	}
	return dbManager.GetNewMessages(username, peer, since)
}

// Обновляем функцию отправки сообщения
func sendMessageUI() {
	// Защита от паники
	defer func() {
		if r := recover(); r != nil {
			LogError("КРИТИЧЕСКАЯ ОШИБКА при отправке сообщения: %v", r)
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			LogDebug("Стек вызовов: %s", buf[:n])

			// Показываем сообщение об ошибке пользователю
			fyne.Do(func() {
				if MainWindow != nil {
					dialog.ShowError(fmt.Errorf("произошла ошибка при отправке сообщения"), MainWindow)
				}
			})
		}
	}()

	if CurrentPeer == "" {
		uiShowError("Выберите пира для отправки сообщения.")
		return
	}

	// Безопасно получаем текст сообщения
	var text string
	if messageEntry != nil {
		text = messageEntry.Text
	} else {
		uiShowError("Ошибка инициализации интерфейса.")
		return
	}

	if text == "" {
		return
	}

	// Поиск адреса пира и проверка его доступности
	var peerAddress string
	var isOnline bool

	peersMutex.RLock()
	for addr, peer := range peers {
		if peer.Name == CurrentPeer {
			peerAddress = addr
			isOnline = peer.IsOnline
			break
		}
	}
	peersMutex.RUnlock()

	if peerAddress == "" {
		uiShowError("Пир не найден.")
		return
	}

	if !isOnline {
		uiShowError("Пир в данный момент не в сети. Сообщение не может быть доставлено.")
		return
	}

	// Сначала проверяем соединение с пиром перед отправкой сообщения
	// Формируем и отправляем ping запрос
	pingMessage := Message{
		Type:      "heartbeat",
		Sender:    username,
		Timestamp: time.Now().Unix(),
	}

	pingData, err := json.Marshal(pingMessage)
	if err != nil {
		LogError("Ошибка при создании ping-сообщения: %v", err)
		uiShowError("Ошибка при проверке доступности пира.")
		return
	}

	// Проверка соединения с пиром
	if err := sendTCPDataWithTimeout(peerAddress, tcpPort, pingData, 1*time.Second); err != nil {
		LogError("Пир %s недоступен: %v", peerAddress, err)
		uiShowError("Не удается установить соединение с пиром. Проверьте подключение и доступность получателя.")

		// Обновляем статус пира как оффлайн
		peersMutex.Lock()
		if peer, exists := peers[peerAddress]; exists {
			peer.IsOnline = false
			peers[peerAddress] = peer
		}
		peersMutex.Unlock()

		return
	}

	// Отправка сообщения
	LogDebug("Отправка сообщения пиру %s (%s)", CurrentPeer, peerAddress)
	err = sendEncryptedMessage(peerAddress, text)
	if err != nil {
		LogError("Ошибка отправки сообщения: %v", err)
		uiShowError("Ошибка отправки сообщения: " + err.Error())
		return
	}

	// Создаем запись о сообщении
	timestamp := time.Now().Unix()
	newMessage := MessageRecord{
		Sender:    username,
		Recipient: CurrentPeer,
		Content:   text,
		Timestamp: timestamp,
	}

	// Добавляем сообщение через общую функцию
	addMessage(newMessage)

	// Очищаем поле ввода
	fyne.Do(func() {
		if messageEntry != nil {
			messageEntry.SetText("")
		}
	})

	// Сохраняем сообщение в базу данных
	if dbEnabled {
		saveMessage(username, CurrentPeer, text, timestamp)
	}
}

// uiShowError отображает сообщение об ошибке
func uiShowError(message string) {
	fyne.Do(func() {
		dialog.ShowError(errors.New(message), MainWindow)
	})
}

func NewPeerListItem(peer Peer) *PeerListItem {
	item := &PeerListItem{peer: peer}
	item.ExtendBaseWidget(item)
	return item
}
