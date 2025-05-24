package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	discoveryPort      = 55555 // Порт для обнаружения пиров (ранее UDP порт)
	discoveryTCPMsg    = "SWAGNET_DISCOVERY"
	discoveryPingDelay = 5 * time.Second // Период отправки discovery ping
)

var (
	isScanning int32 // Флаг для отслеживания процесса сканирования
	// Последние успешно найденные адреса пиров
	lastKnownPeers      = make(map[string]time.Time)
	lastKnownPeersMutex sync.RWMutex
)

// startDiscoveryTCPServer запускает TCP сервер для обнаружения пиров
func startDiscoveryTCPServer(peers chan<- Peer) {
	log.Println("Запуск TCP сервера обнаружения пиров")

	// Попытаемся использовать несколько портов, если основной занят
	var err error
	maxRetries := 3
	portOffset := 0
	var currentPort int

	for i := 0; i < maxRetries; i++ {
		currentPort = discoveryPort + portOffset
		currentAddr := net.JoinHostPort("", fmt.Sprintf("%d", currentPort))

		// Защита от одновременного доступа
		networkMutex.Lock()
		discoveryListener, err = net.Listen("tcp", currentAddr)
		networkMutex.Unlock()

		if err == nil {
			// Порт успешно занят
			log.Printf("TCP сервер обнаружения успешно запущен на порту %d", currentPort)
			fmt.Printf("\nTCP сервер обнаружения запущен на порту %d\n", currentPort)

			break
		}

		log.Printf("Не удалось запустить TCP сервер обнаружения на порту %d: %v, попытка %d",
			currentPort, err, i+1)
		portOffset++
	}

	if err != nil {
		log.Printf("Ошибка запуска TCP сервера обнаружения после %d попыток: %v", maxRetries, err)
		fmt.Printf("\nОшибка запуска TCP сервера обнаружения: %v\n", err)
		if peers != nil {
			close(peers)
		}
		return
	}

	// Запускаем сервис периодического оповещения
	go announcePeers()

	// Обрабатываем входящие соединения в отдельной горутине
	go func() {
		for running {
			// Используем глобальную переменную вместо локальной
			conn, err := discoveryListener.Accept()
			if err != nil {
				if !running {
					break
				}
				log.Printf("Ошибка принятия соединения обнаружения: %v", err)
				continue
			}
			go handleDiscoveryConnection(conn, peers)
		}
	}()
}

// handleDiscoveryConnection обрабатывает входящее TCP соединение для обнаружения пиров
func handleDiscoveryConnection(conn net.Conn, peers chan<- Peer) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("Получено discovery соединение от %s", remoteAddr)

	// Буфер для чтения
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("Ошибка чтения из соединения %s: %v", remoteAddr, err)
		GetEventBus().Publish(NetworkEvent{
			Type: EventError,
			Payload: NetworkError{
				Message: fmt.Sprintf("Ошибка чтения из соединения %s", remoteAddr),
				Err:     err,
			},
		})
		return
	}

	// Обрабатываем полученное сообщение
	message := string(buffer[:n])
	log.Printf("Получено discovery сообщение: %s", message)

	// Если это запрос на обнаружение, отправляем свои данные
	if message == discoveryTCPMsg {
		// Отправляем информацию о себе
		log.Printf("Отправка информации о себе в ответ на запрос от %s", remoteAddr)
		pubKeyPEM := getPublicKeyPEM()
		response := fmt.Sprintf("SWAGNET_PEER|%s|%s", username, pubKeyPEM)
		conn.Write([]byte(response))
	} else if strings.HasPrefix(message, "SWAGNET_PEER|") {
		// Если это информация о пире
		parts := strings.Split(message, "|")
		if len(parts) == 3 {
			peerName := parts[1]
			pubKeyPEM := parts[2]
			pubKey := parsePublicKeyPEM(pubKeyPEM)

			// Извлекаем IP адрес из remoteAddr (убираем порт)
			host, _, err := net.SplitHostPort(remoteAddr)
			if err != nil {
				log.Printf("Ошибка извлечения адреса из %s: %v", remoteAddr, err)
				GetEventBus().Publish(NetworkEvent{
					Type: EventError,
					Payload: NetworkError{
						Message: fmt.Sprintf("Ошибка извлечения адреса из %s", remoteAddr),
						Err:     err,
					},
				})
				return
			}

			// Проверяем, не является ли это нашим собственным подключением
			if peerName == username {
				log.Printf("Игнорирование собственного подключения от %s с именем %s", host, peerName)
				return
			}

			if isLocalIP(host) {
				log.Printf("Игнорирование локального IP адреса: %s", host)
				return
			}

			if pubKey != nil {
				log.Printf("Получена информация о пире: %s (%s)", peerName, host)
				newPeer := Peer{
					Address:   host,
					Name:      peerName,
					PublicKey: pubKey,
				}

				// Обновляем список приоритетных адресов
				updateLastKnownPeer(host)

				if peers != nil {
					peers <- newPeer
				}

				GetEventBus().Publish(NetworkEvent{
					Type:    EventPeerDiscovered,
					Payload: newPeer,
				})
			} else {
				log.Printf("Ошибка парсинга публичного ключа от пира %s", peerName)
				GetEventBus().Publish(NetworkEvent{
					Type: EventError,
					Payload: NetworkError{
						Message: fmt.Sprintf("Ошибка парсинга публичного ключа от пира %s", peerName),
						Err:     errors.New("invalid public key"),
					},
				})
			}
		}
	}
}

// announcePeers выполняет начальное сканирование сети
func announcePeers() {
	log.Println("Запуск начального сканирования сети")

	// Получаем список IP адресов для сканирования
	ips := getLocalNetworkIPs()

	// Выполняем начальное сканирование
	scanNetwork(ips)

	// После начального сканирования только поддерживаем соединения с известными пирами
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for running {
		<-ticker.C
		// Проверяем только известные пиры
		priorityIPs := getPriorityIPs()
		if len(priorityIPs) > 0 {
			// Создаем контекст для быстрого сканирования известных пиров
			ctx := context.Background()
			scanNetworkWithContext(ctx, priorityIPs)
		}
	}
}

// startManualScan запускает сканирование сети по запросу пользователя
func startManualScan() {
	if !atomic.CompareAndSwapInt32(&isScanning, 0, 1) {
		log.Println("Сканирование уже выполняется")
		return
	}

	go func() {
		defer atomic.StoreInt32(&isScanning, 0)
		ips := getLocalNetworkIPs()
		scanNetwork(ips)
	}()
}

// scanNetwork сканирует сеть на наличие других пиров
func scanNetwork(ips []string) {
	log.Println("Сканирование сети на наличие пиров")

	// Создаем контекст для сканирования
	ctx := context.Background()
	scanNetworkWithContext(ctx, ips)
}

// scanNetworkWithContext сканирует сеть с поддержкой контекста для отмены
func scanNetworkWithContext(ctx context.Context, ips []string) {
	log.Println("Сканирование сети на наличие пиров")

	GetEventBus().Publish(NetworkEvent{
		Type:    EventScanStarted,
		Payload: nil,
	})

	defer func() {
		GetEventBus().Publish(NetworkEvent{
			Type:    EventScanFinished,
			Payload: nil,
		})
	}()

	// Создаем waitgroup для отслеживания горутин
	var wg sync.WaitGroup

	// Защита от некорректных входных данных
	if len(ips) == 0 {
		log.Println("ПРЕДУПРЕЖДЕНИЕ: Пустой список IP адресов для сканирования")
		return
	}

	// Счетчики для статистики
	var successCount, failCount, peerCount int32

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

		// Пропускаем пустые или некорректные IP
		if ip == "" || !isValidIP(ip) {
			log.Printf("Пропускаем некорректный IP: %s", ip)
			continue
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
			defer func() {
				wg.Done()
				<-semaphore // Освобождаем слот в семафоре
				if r := recover(); r != nil {
					log.Printf("КРИТИЧЕСКАЯ ОШИБКА: Паника при сканировании IP %s: %v", ip, r)
					// Запись стека вызовов для отладки
					buf := make([]byte, 4096)
					n := runtime.Stack(buf, false)
					log.Printf("Стек вызовов: %s", buf[:n])
					atomic.AddInt32(&failCount, 1)
				}
			}()

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
				atomic.AddInt32(&failCount, 1)
				return
			}

			// Устанавливаем дедлайн для всех операций с соединением
			conn.SetDeadline(time.Now().Add(500 * time.Millisecond))

			// Отправляем запрос обнаружения
			if _, err := conn.Write([]byte(discoveryTCPMsg)); err != nil {
				conn.Close()
				atomic.AddInt32(&failCount, 1)
				return
			}

			// Ждем и читаем ответ
			buffer := make([]byte, 2048)
			n, err := conn.Read(buffer)
			conn.Close() // Закрываем соединение сразу после чтения
			if err != nil {
				atomic.AddInt32(&failCount, 1)
				return
			}

			atomic.AddInt32(&successCount, 1)
			message := string(buffer[:n])
			log.Printf("Получен ответ от %s: %s", addr, message)

			// Обрабатываем ответ
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
							LastSeen:  time.Now(),
							IsOnline:  true,
						}
						peersMutex.Unlock()

						log.Printf("Добавлен новый пир: %s (%s)", peerName, ip)
						atomic.AddInt32(&peerCount, 1)

						// Уведомляем о новом пире
						GetEventBus().Publish(NetworkEvent{
							Type: EventPeerDiscovered,
							Payload: Peer{
								Address:   ip,
								Name:      peerName,
								PublicKey: pubKey,
								LastSeen:  time.Now(),
								IsOnline:  true,
							},
						})

						// Уведомляем UI о новом пире
						if uiEnabled {
							// Безопасно обновляем UI через отдельную функцию
							safeUpdateUI()
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
		log.Printf("Сканирование сети завершено успешно: проверено %d IP, успешно %d, найдено пиров %d",
			atomic.LoadInt32(&successCount)+atomic.LoadInt32(&failCount),
			atomic.LoadInt32(&successCount),
			atomic.LoadInt32(&peerCount))
	case <-ctx.Done():
		log.Println("Сканирование сети отменено")
	}

	// После завершения сканирования
	GetEventBus().Publish(NetworkEvent{
		Type: EventScanFinished,
		Payload: struct {
			SuccessCount int32
			FailCount    int32
			PeerCount    int32
		}{
			SuccessCount: atomic.LoadInt32(&successCount),
			FailCount:    atomic.LoadInt32(&failCount),
			PeerCount:    atomic.LoadInt32(&peerCount),
		},
	})
}

// isValidIP проверяет валидность IP адреса
func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// getLocalNetworkIPs получает список IP адресов для сканирования в локальной сети
func getLocalNetworkIPs() []string {
	var ips []string
	var vpnIPs []string

	// Получаем все локальные интерфейсы
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("Ошибка получения сетевых интерфейсов: %v", err)
		return ips
	}

	for _, iface := range interfaces {
		// Пропускаем выключенные интерфейсы и loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue // Пропускаем не IPv4 адреса
			}

			// Определяем тип сети
			isVPN := isVPNInterface(iface.Name) || !isPrivateNetwork(ipnet)

			// Получаем диапазон IP адресов для сканирования
			network := generateIPRange(ipnet)

			if isVPN {
				vpnIPs = append(vpnIPs, network...)
				log.Printf("Обнаружен VPN интерфейс %s с адресами: %v", iface.Name, network)
			} else {
				ips = append(ips, network...)
				log.Printf("Обнаружен локальный интерфейс %s с адресами: %v", iface.Name, network)
			}
		}
	}

	// Если есть и VPN и локальные адреса, используем оба набора
	if len(vpnIPs) > 0 && len(ips) > 0 {
		log.Printf("Обнаружены как VPN (%d), так и локальные (%d) адреса", len(vpnIPs), len(ips))
		ips = append(ips, vpnIPs...)
	} else if len(ips) == 0 && len(vpnIPs) > 0 {
		// Если есть только VPN адреса, используем их
		log.Println("Обнаружены только VPN адреса, используем их для сканирования")
		ips = vpnIPs
	} else if len(ips) == 0 {
		log.Println("Не удалось получить список IP адресов, используем стандартный диапазон")
		// Сканируем адреса 192.168.1.1-192.168.1.254
		for i := 1; i < 255; i++ {
			ips = append(ips, fmt.Sprintf("192.168.1.%d", i))
		}
	}

	return ips
}

// generateIPRange генерирует список IP адресов для сканирования на основе сети
func generateIPRange(ipnet *net.IPNet) []string {
	var ips []string
	ip := ipnet.IP.To4()

	// Сначала добавляем приоритетные адреса
	priorityIPs := getPriorityIPs()
	if len(priorityIPs) > 0 {
		log.Printf("Найдено %d приоритетных адресов для сканирования", len(priorityIPs))
		ips = append(ips, priorityIPs...)
	}

	// Создаем множество приоритетных адресов для быстрой проверки
	prioritySet := make(map[string]bool)
	for _, pip := range priorityIPs {
		prioritySet[pip] = true
	}

	// Для всех сетей используем стандартный диапазон с ограничением в 254 адреса
	maxIPs := 254 - len(priorityIPs) // Уменьшаем максимум на количество приоритетных адресов
	if maxIPs <= 0 {
		return ips // Возвращаем только приоритетные адреса
	}

	// Проверяем маску - если сеть слишком большая, сканируем только подсеть /24
	ones, _ := ipnet.Mask.Size()
	if ones < 24 {
		log.Printf("Сеть %s слишком большая, сканируем только подсеть /24", ipnet.String())
		baseIP := fmt.Sprintf("%d.%d.%d.", ip[0], ip[1], ip[2])

		// Генерируем адреса от 1 до 254, исключая приоритетные
		for i := 1; i < 255; i++ {
			newIP := baseIP + fmt.Sprintf("%d", i)
			if !prioritySet[newIP] {
				ips = append(ips, newIP)
			}
		}
		return ips
	}

	// Для небольших сетей сканируем весь диапазон
	first := ip.Mask(ipnet.Mask)
	last := make(net.IP, len(ip))
	copy(last, ip)
	for i := 0; i < len(ipnet.Mask); i++ {
		last[i] = ip[i] | ^ipnet.Mask[i]
	}

	firstIP := ipToUint32(first)
	lastIP := ipToUint32(last)

	// Добавляем все адреса, исключая приоритетные
	for i := firstIP + 1; i < lastIP; i++ {
		newIP := uint32ToIP(i).String()
		if !prioritySet[newIP] {
			ips = append(ips, newIP)
		}
	}

	return ips
}

// ipToUint32 преобразует IP адрес в uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// uint32ToIP преобразует uint32 в IP адрес
func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// isLocalIP проверяет, является ли IP адрес локальным
// или принадлежит текущему компьютеру
func isLocalIP(ipStr string) bool {
	// Обрабатываем пустые строки
	if ipStr == "" {
		return true
	}

	// Обрезаем зону для IPv6 адресов (часть после %)
	ipWithoutZone := ipStr
	if idx := strings.Index(ipStr, "%"); idx != -1 {
		ipWithoutZone = ipStr[:idx]
		log.Printf("Обрабатываем IPv6 адрес с зоной: %s (без зоны: %s)", ipStr, ipWithoutZone)
	}

	// Проверка на валидность IP
	ip := net.ParseIP(ipWithoutZone)
	if ip == nil {
		log.Printf("Невалидный IP адрес: %s", ipStr)
		return false
	}

	// Быстрые проверки на специальные адреса
	if ip.IsLoopback() {
		log.Printf("IP %s - это loopback адрес", ipStr)
		return true
	}

	if ip.IsUnspecified() {
		log.Printf("IP %s - это неспецифицированный адрес", ipStr)
		return true
	}

	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		log.Printf("IP %s - это link-local адрес", ipStr)
		return true
	}

	// Проверка на совпадение с собственным именем пользователя
	var nameMatch bool
	peersMutex.RLock()
	for _, peer := range peers {
		if peer.Name == username && strings.HasPrefix(peer.Address, ipWithoutZone) {
			nameMatch = true
			break
		}
	}
	peersMutex.RUnlock()

	if nameMatch {
		log.Printf("IP %s связан с текущим пользователем %s", ipStr, username)
		return true
	}

	// Получаем все локальные адреса
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("Ошибка получения локальных интерфейсов: %v", err)
		return false
	}

	// Сравниваем с каждым локальным адресом
	for _, addr := range addrs {
		var localIP net.IP
		var ipNet *net.IPNet

		switch v := addr.(type) {
		case *net.IPNet:
			localIP = v.IP
			ipNet = v
		case *net.IPAddr:
			localIP = v.IP
		}

		if localIP == nil {
			continue
		}

		// Убираем зону, если она есть
		localIPStr := localIP.String()
		if idx := strings.Index(localIPStr, "%"); idx != -1 {
			localIPStr = localIPStr[:idx]
		}

		// Прямое сравнение IP адресов
		if ipWithoutZone == localIPStr {
			log.Printf("IP %s совпадает с локальным %s", ipStr, localIPStr)
			return true
		}

		// Сравнение через IP.Equal для учета разных форматов записи
		if localIP.Equal(ip) {
			log.Printf("IP %s совпадает с локальным %s (через Equal)", ipStr, localIPStr)
			return true
		}

		// Для VPN интерфейсов проверяем только точное совпадение
		if ipNet != nil && isVPNInterface(getInterfaceNameByIP(localIP)) {
			continue
		}

		// Для локальных сетей проверяем принадлежность подсети
		if ipNet != nil && ipNet.Contains(ip) && isPrivateNetwork(ipNet) {
			log.Printf("IP %s находится в локальной подсети %s", ipStr, ipNet)
			return true
		}
	}

	return false
}

// getInterfaceNameByIP получает имя интерфейса по IP адресу
func getInterfaceNameByIP(ip net.IP) string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				if v.IP.Equal(ip) {
					return iface.Name
				}
			case *net.IPAddr:
				if v.IP.Equal(ip) {
					return iface.Name
				}
			}
		}
	}

	return ""
}

// processPeers обрабатывает обнаруженных пиров
func processPeers(discoveredPeers <-chan Peer) {
	if discoveredPeers == nil {
		log.Println("ОШИБКА: Канал обнаружения пиров не инициализирован")
		return
	}

	log.Println("Запущен процесс обработки обнаруженных пиров")

	for running {
		// Заменяем select с одним case на прямое чтение из канала
		peer, ok := <-discoveredPeers
		if !ok {
			log.Println("Канал обнаружения пиров закрыт, завершаем обработку")
			return
		}

		// Проверяем валидность данных пира
		if peer.Address == "" || peer.Name == "" || peer.PublicKey == nil {
			log.Printf("ПРЕДУПРЕЖДЕНИЕ: Получены некорректные данные пира: %+v", peer)
			continue
		}

		// Добавляем пира в список с блокировкой
		peersMutex.Lock()
		_, exists := peers[peer.Address]
		peers[peer.Address] = peer
		peersMutex.Unlock()

		if exists {
			log.Printf("Обновлен существующий пир: %s (%s)", peer.Name, peer.Address)
		} else {
			log.Printf("Добавлен новый пир: %s (%s)", peer.Name, peer.Address)
		}

		// Обновляем UI, если он включен
		if uiEnabled {
			// Проверяем активность UI перед обновлением
			uiMutex.Lock()
			isUIActive := uiActive
			uiMutex.Unlock()

			if isUIActive && running {
				log.Printf("Обновляем UI после обнаружения пира %s", peer.Name)
				safeUpdateUI()
			} else {
				log.Println("UI не активен, пропускаем обновление")
			}
		} else {
			// Консольный режим (если UI не включен)
			fmt.Printf("\nНайден новый пир: %s (%s)\n", peer.Name, peer.Address)
			printPrompt()
		}

		// Сохраняем пира в базу данных
		if dbEnabled {
			err := savePeerInfo(peer)
			if err != nil {
				log.Printf("Ошибка сохранения информации о пире %s: %v", peer.Name, err)
			}
		}
	}
}

// isVPNInterface определяет является ли интерфейс VPN-интерфейсом
func isVPNInterface(ifaceName string) bool {
	// Типичные имена VPN интерфейсов
	vpnPatterns := []string{
		"tun", "tap", "ppp", "vpn", "wg", "nordlynx",
		"proton", "mullvad", "wireguard", "openvpn",
	}

	ifaceName = strings.ToLower(ifaceName)
	for _, pattern := range vpnPatterns {
		if strings.Contains(ifaceName, pattern) {
			return true
		}
	}
	return false
}

// isPrivateNetwork проверяет является ли сеть частной (локальной)
func isPrivateNetwork(ipnet *net.IPNet) bool {
	// Определяем частные диапазоны IP адресов (RFC 1918)
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{
			net.ParseIP("10.0.0.0"),
			net.ParseIP("10.255.255.255"),
		},
		{
			net.ParseIP("172.16.0.0"),
			net.ParseIP("172.31.255.255"),
		},
		{
			net.ParseIP("192.168.0.0"),
			net.ParseIP("192.168.255.255"),
		},
	}

	ip := ipnet.IP.To4()
	if ip == nil {
		return false
	}

	for _, r := range privateRanges {
		if bytes.Compare(ip, r.start) >= 0 && bytes.Compare(ip, r.end) <= 0 {
			return true
		}
	}
	return false
}

// updateLastKnownPeer обновляет информацию о последнем известном пире
func updateLastKnownPeer(ip string) {
	lastKnownPeersMutex.Lock()
	defer lastKnownPeersMutex.Unlock()
	lastKnownPeers[ip] = time.Now()
	// Очищаем старые записи (старше 1 часа)
	for ip, lastSeen := range lastKnownPeers {
		if time.Since(lastSeen) > 1*time.Hour {
			delete(lastKnownPeers, ip)
		}
	}
}

// getPriorityIPs возвращает список приоритетных IP адресов для сканирования
func getPriorityIPs() []string {
	lastKnownPeersMutex.RLock()
	defer lastKnownPeersMutex.RUnlock()

	priorityIPs := make([]string, 0, len(lastKnownPeers))
	for ip, lastSeen := range lastKnownPeers {
		// Включаем только адреса, которые были активны в последний час
		if time.Since(lastSeen) <= 1*time.Hour {
			priorityIPs = append(priorityIPs, ip)
		}
	}
	return priorityIPs
}
