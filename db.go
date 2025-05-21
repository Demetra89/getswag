package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

var (
	db        *bbolt.DB
	dbEnabled bool
)

const (
	dbDir          = "data"
	dbFile         = "messages.db"
	messagesBucket = "messages"
	peersBucket    = "peers"
)

// MessageRecord представляет запись сообщения в базе данных
type MessageRecord struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
}

// initDB инициализирует базу данных BoltDB
func initDB() error {
	log.Println("Инициализация базы данных")

	// Создаем директорию для базы данных, если она не существует
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		log.Printf("Ошибка создания директории для базы данных: %v", err)
		return err
	}

	dbPath := filepath.Join(dbDir, dbFile)
	log.Printf("Путь к базе данных: %s", dbPath)

	var err error
	db, err = bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
	if err != nil {
		log.Printf("Ошибка открытия базы данных: %v", err)
		return err
	}

	// Создаем необходимые бакеты
	err = db.Update(func(tx *bbolt.Tx) error {
		// Создаем бакет для сообщений
		_, err := tx.CreateBucketIfNotExists([]byte(messagesBucket))
		if err != nil {
			return fmt.Errorf("ошибка создания бакета сообщений: %v", err)
		}

		// Создаем бакет для пиров
		_, err = tx.CreateBucketIfNotExists([]byte(peersBucket))
		if err != nil {
			return fmt.Errorf("ошибка создания бакета пиров: %v", err)
		}

		return nil
	})

	if err != nil {
		log.Printf("Ошибка инициализации бакетов: %v", err)
		return err
	}

	log.Println("База данных успешно инициализирована")
	dbEnabled = true
	return nil
}

// closeDB закрывает базу данных
func closeDB() {
	if db != nil {
		db.Close()
		log.Println("База данных закрыта")
	}
}

// saveMessage сохраняет сообщение в базу данных
func saveMessage(sender, recipient, content string, timestamp int64) error {
	if !dbEnabled || db == nil {
		log.Println("База данных не инициализирована, сообщение не сохранено")
		return fmt.Errorf("база данных не инициализирована")
	}

	// Создаем запись сообщения
	message := MessageRecord{
		Sender:    sender,
		Recipient: recipient,
		Content:   content,
		Timestamp: timestamp,
	}

	// Сериализуем в JSON
	messageJSON, err := json.Marshal(message)
	if err != nil {
		log.Printf("Ошибка маршаллинга сообщения: %v", err)
		return err
	}

	// Создаем ключ в формате timestamp_sender_recipient
	key := fmt.Sprintf("%d_%s_%s", timestamp, sender, recipient)

	// Сохраняем в базу данных
	err = db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(messagesBucket))
		return b.Put([]byte(key), messageJSON)
	})

	if err != nil {
		log.Printf("Ошибка сохранения сообщения в базу данных: %v", err)
		return err
	}

	log.Printf("Сообщение успешно сохранено в базу данных с ключом: %s", key)
	return nil
}

// getMessagesWithPeer возвращает историю сообщений с указанным пиром
func getMessagesWithPeer(peerName string) ([]MessageRecord, error) {
	if !dbEnabled || db == nil {
		log.Println("База данных не инициализирована")
		return nil, fmt.Errorf("база данных не инициализирована")
	}

	var messages []MessageRecord

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(messagesBucket))

		return b.ForEach(func(k, v []byte) error {
			var msg MessageRecord
			if err := json.Unmarshal(v, &msg); err != nil {
				return err
			}

			// Выбираем сообщения, относящиеся к этому пиру
			if (msg.Sender == peerName && msg.Recipient == username) ||
				(msg.Sender == username && msg.Recipient == peerName) {
				messages = append(messages, msg)
			}

			return nil
		})
	})

	if err != nil {
		log.Printf("Ошибка получения сообщений из базы данных: %v", err)
		return nil, err
	}

	log.Printf("Получено %d сообщений с пиром %s", len(messages), peerName)
	return messages, nil
}

// savePeerInfo сохраняет информацию о пире в базу данных
func savePeerInfo(peer Peer) error {
	if !dbEnabled || db == nil {
		log.Println("База данных не инициализирована")
		return fmt.Errorf("база данных не инициализирована")
	}

	// Сериализуем публичный ключ в PEM
	pubKeyPEM := getPublicKeyPEM()

	// Создаем структуру для хранения
	peerInfo := struct {
		Name      string `json:"name"`
		Address   string `json:"address"`
		PublicKey string `json:"public_key"`
	}{
		Name:      peer.Name,
		Address:   peer.Address,
		PublicKey: pubKeyPEM,
	}

	// Сериализуем в JSON
	peerJSON, err := json.Marshal(peerInfo)
	if err != nil {
		log.Printf("Ошибка маршаллинга информации о пире: %v", err)
		return err
	}

	// Сохраняем в базу данных
	err = db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(peersBucket))
		return b.Put([]byte(peer.Name), peerJSON)
	})

	if err != nil {
		log.Printf("Ошибка сохранения информации о пире в базу данных: %v", err)
		return err
	}

	log.Printf("Информация о пире %s успешно сохранена в базу данных", peer.Name)
	return nil
}

// loadPeers загружает сохраненных пиров из базы данных
func loadPeers() error {
	if !dbEnabled || db == nil {
		log.Println("База данных не инициализирована")
		return fmt.Errorf("база данных не инициализирована")
	}

	err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(peersBucket))

		return b.ForEach(func(k, v []byte) error {
			var peerInfo struct {
				Name      string `json:"name"`
				Address   string `json:"address"`
				PublicKey string `json:"public_key"`
			}

			if err := json.Unmarshal(v, &peerInfo); err != nil {
				return err
			}

			// Парсим публичный ключ
			pubKey := parsePublicKeyPEM(peerInfo.PublicKey)
			if pubKey == nil {
				log.Printf("Ошибка парсинга публичного ключа для пира %s", peerInfo.Name)
				return nil // Пропускаем этого пира, но продолжаем загрузку других
			}

			// Добавляем пира в список
			peersMutex.Lock()
			peers[peerInfo.Address] = Peer{
				Name:      peerInfo.Name,
				Address:   peerInfo.Address,
				PublicKey: pubKey,
			}
			peersMutex.Unlock()

			log.Printf("Загружен пир из базы данных: %s (%s)", peerInfo.Name, peerInfo.Address)

			return nil
		})
	})

	if err != nil {
		log.Printf("Ошибка загрузки пиров из базы данных: %v", err)
		return err
	}

	peersMutex.RLock()
	defer peersMutex.RUnlock()
	log.Printf("Загружено %d пиров из базы данных", len(peers))

	return nil
}
