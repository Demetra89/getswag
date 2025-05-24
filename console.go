package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

// runConsoleUI запускает консольный интерфейс
func runConsoleUI() {
	reader := bufio.NewReader(os.Stdin)
	printPrompt()

	for running {
		input, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("Ошибка чтения ввода: %v", err)
			continue
		}

		input = strings.TrimSpace(input)
		if input == "" {
			printPrompt()
			continue
		}

		handleConsoleCommand(input)
	}
}

// handleConsoleCommand обрабатывает команды консоли
func handleConsoleCommand(input string) {
	if input[0] == '/' {
		// Обработка команд
		parts := strings.SplitN(input[1:], " ", 2)
		cmd := parts[0]

		switch cmd {
		case "help":
			printHelp()
		case "scan":
			scanNetwork(getLocalNetworkIPs())
		case "peers":
			listPeers()
		case "quit", "exit":
			running = false
		default:
			fmt.Println("Неизвестная команда. Введите /help для помощи.")
		}
	} else {
		// Отправка сообщения текущему пиру
		if CurrentPeer == "" {
			fmt.Println("Выберите пира для отправки сообщения.")
			return
		}
		sendMessage(CurrentPeer, input)
	}
	printPrompt()
}

// printPrompt выводит приглашение ввода
func printPrompt() {
	if CurrentPeer != "" {
		fmt.Printf("[%s] > ", CurrentPeer)
	} else {
		fmt.Print(cmdPrompt)
	}
}

// printHelp выводит справку по командам
func printHelp() {
	fmt.Println("\nДоступные команды:")
	fmt.Println("/help   - показать эту справку")
	fmt.Println("/scan   - сканировать сеть")
	fmt.Println("/peers  - показать список пиров")
	fmt.Println("/quit   - выйти из программы")
	fmt.Println("\nДля отправки сообщения просто введите текст.")
}

// listPeers выводит список доступных пиров
func listPeers() {
	peersMutex.RLock()
	defer peersMutex.RUnlock()

	if len(peers) == 0 {
		fmt.Println("Нет доступных пиров.")
		return
	}

	fmt.Println("\nДоступные пиры:")
	for _, peer := range peers {
		status := "оффлайн"
		if peer.IsOnline {
			status = "онлайн"
		}
		fmt.Printf("- %s (%s) [%s]\n", peer.Name, peer.Address, status)
	}
}
