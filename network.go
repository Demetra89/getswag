package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	discoveryPort      = 55555 // Порт для обнаружения пиров (ранее UDP порт)
	discoveryTCPMsg    = "SWAGNET_DISCOVERY"
	discoveryPingDelay = 5 * time.Second // Период отправки discovery ping
)

// startDiscoveryTCPServer запускает TCP сервер для обнаружения пиров
func startDiscoveryTCPServer(peers chan<- Peer) {
	log.Println("Запуск TCP сервера обнаружения пиров")

	// Слушаем на всех интерфейсах
	addr := net.JoinHostPort("", fmt.Sprintf("%d", discoveryPort))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Ошибка запуска TCP сервера обнаружения: %v", err)
		fmt.Printf("\nОшибка запуска TCP сервера обнаружения: %v\n", err)
		if peers != nil {
			close(peers)
		}
		return
	}
	defer listener.Close()

	log.Printf("TCP сервер обнаружения запущен на порту %d", discoveryPort)
	fmt.Printf("\nTCP сервер обнаружения запущен на порту %d\n", discoveryPort)

	// Запускаем сервис периодического оповещения
	go announcePeers()

	for running {
		conn, err := listener.Accept()
		if err != nil {
			if !running {
				break
			}
			log.Printf("Ошибка принятия соединения: %v", err)
			continue
		}
		go handleDiscoveryConnection(conn, peers)
	}
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
				return
			}

			if pubKey != nil {
				log.Printf("Получена информация о пире: %s (%s)", peerName, host)
				if peers != nil {
					peers <- Peer{
						Address:   host,
						Name:      peerName,
						PublicKey: pubKey,
					}
				}
			} else {
				log.Printf("Ошибка парсинга публичного ключа от пира %s", peerName)
			}
		}
	}
}

// announcePeers периодически отправляет сообщения для объявления о себе
// и поиска других пиров в сети
func announcePeers() {
	log.Println("Запуск периодического оповещения о наличии пира")

	// Получаем список IP адресов для сканирования
	ips := getLocalNetworkIPs()

	ticker := time.NewTicker(discoveryPingDelay)
	defer ticker.Stop()

	for running {
		<-ticker.C
		scanNetwork(ips)
	}
}

// scanNetwork сканирует сеть на наличие других пиров
func scanNetwork(ips []string) {
	log.Println("Сканирование сети на наличие пиров")

	// Ограничиваем общее время сканирования
	scanTimeout := 20 * time.Second
	deadline := time.Now().Add(scanTimeout)

	// Создаем канал для отмены и waitgroup для отслеживания горутин
	done := make(chan struct{})
	defer close(done)

	var wg sync.WaitGroup

	// Канал для ограничения количества одновременных соединений
	semaphore := make(chan struct{}, 20) // максимум 20 одновременных соединений

	// Отображаем прогресс, если UI выключен
	if !uiEnabled {
		fmt.Println("Сканирование сети. Это может занять некоторое время...")
	}

	// Сканируем параллельно
	for _, ip := range ips {
		// Проверяем на превышение таймаута
		if time.Now().After(deadline) {
			log.Println("Превышено время сканирования, останавливаем процесс")
			break
		}

		// Пропускаем подключение к себе
		if isLocalIP(ip) {
			continue
		}

		// Ожидаем доступного слота в семафоре
		select {
		case semaphore <- struct{}{}:
			// Слот доступен, продолжаем
		case <-done:
			// Сканирование отменено
			return
		}

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Освобождаем слот в семафоре

			// Проверяем на отмену перед каждым новым подключением
			select {
			case <-done:
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

			// Обрабатываем ответ от сервера как информацию о пире
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
						} else {
							fmt.Printf("\nНайден новый пир: %s (%s)\n", peerName, ip)
							printPrompt()
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

	// Создаем таймер для ограничения времени ожидания
	timeout := time.AfterFunc(scanTimeout, func() {
		close(done) // Отменяем все текущие операции
	})
	defer timeout.Stop()

	// Ожидаем завершения всех горутин или таймаута
	done_waiting := make(chan struct{})
	go func() {
		wg.Wait()
		close(done_waiting)
	}()

	// Ждем либо завершения всех горутин, либо таймаута
	select {
	case <-done_waiting:
		log.Println("Сканирование сети завершено успешно")
	case <-time.After(scanTimeout):
		log.Println("Сканирование сети остановлено по таймауту")
	}

	if !uiEnabled {
		fmt.Println("Сканирование сети завершено")
		printPrompt()
	}
}

// getLocalNetworkIPs получает список IP адресов для сканирования в локальной сети
func getLocalNetworkIPs() []string {
	var ips []string

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

			// Получаем диапазон IP адресов для сканирования
			network := generateIPRange(ipnet)
			ips = append(ips, network...)
		}
	}

	// Если не удалось получить список IP, используем стандартный диапазон
	if len(ips) == 0 {
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
	mask := ipnet.Mask

	// Ограничиваем количество адресов для сканирования до 254
	// (чтобы не сканировать огромные сети)
	maxIPs := 254

	// Проверяем маску - если сеть слишком большая, сканируем только подсеть /24
	ones, _ := mask.Size()
	if ones < 24 {
		log.Printf("Сеть %s слишком большая, сканируем только подсеть /24", ipnet.String())
		// Берем первые 3 октета и сканируем последний октет
		baseIP := fmt.Sprintf("%d.%d.%d.", ip[0], ip[1], ip[2])
		for i := 1; i < 255; i++ {
			ips = append(ips, baseIP+fmt.Sprintf("%d", i))
		}
		return ips
	}

	// Для небольших сетей сканируем весь диапазон
	// Вычисляем диапазон IP адресов
	first := ip.Mask(mask)
	last := make(net.IP, len(ip))
	copy(last, ip)
	for i := 0; i < len(mask); i++ {
		last[i] = ip[i] | ^mask[i]
	}

	// Преобразуем в uint32 для удобства итерации
	firstIP := ipToUint32(first)
	lastIP := ipToUint32(last)

	// Ограничиваем количество адресов
	if lastIP-firstIP > uint32(maxIPs) {
		lastIP = firstIP + uint32(maxIPs)
	}

	// Пропускаем адрес сети и broadcast
	for i := firstIP + 1; i < lastIP; i++ {
		ips = append(ips, uint32ToIP(i).String())
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
func isLocalIP(ipStr string) bool {
	// Получаем все локальные адреса
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	// Преобразуем строку в IP
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Сравниваем с локальными адресами
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
			if ipnet.IP.To4().Equal(ip.To4()) {
				return true
			}
		}
	}

	return false
}
