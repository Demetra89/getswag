package main

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

const (
	// Database configuration
	DBDir          = "data"
	DBFile         = "messages.db"
	MessagesBucket = "messages"
	PeersBucket    = "peers"
	MetadataBucket = "metadata"

	// Database settings
	DBFileMode   = 0600
	DBDirMode    = 0755
	DBTimeout    = 5 * time.Second
	MaxKeyLength = 250 // BoltDB key limit
)

// MessageRecord представляет запись сообщения в базе данных
type MessageRecord struct {
	ID        string `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
	Encrypted bool   `json:"encrypted"`
	IsRead    bool   `json:"is_read"` // Флаг прочтения сообщения
}

// PeerRecord представляет запись пира в базе данных
type PeerRecord struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	PublicKey string `json:"public_key"`
	LastSeen  int64  `json:"last_seen"`
	Status    string `json:"status"`
}

// DBManager управляет операциями с базой данных
type DBManager struct {
	db     *bbolt.DB
	mu     sync.RWMutex
	path   string
	crypto *CryptoManager
}

// NewDBManager создает новый менеджер базы данных
func NewDBManager(dbPath string, cryptoManager *CryptoManager) *DBManager {
	return &DBManager{
		path:   dbPath,
		crypto: cryptoManager,
	}
}

// Init инициализирует базу данных BoltDB
func (dm *DBManager) Init() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	log.Println("Инициализация базы данных")

	// Создаем директорию для базы данных
	dbDir := filepath.Dir(dm.path)
	if err := os.MkdirAll(dbDir, DBDirMode); err != nil {
		return fmt.Errorf("ошибка создания директории для базы данных: %w", err)
	}

	log.Printf("Путь к базе данных: %s", dm.path)

	// Открываем базу данных с таймаутом
	var err error
	dm.db, err = bbolt.Open(dm.path, DBFileMode, &bbolt.Options{
		Timeout: DBTimeout,
	})
	if err != nil {
		return fmt.Errorf("ошибка открытия базы данных: %w", err)
	}

	// Создаем необходимые бакеты
	if err := dm.createBuckets(); err != nil {
		dm.db.Close()
		return fmt.Errorf("ошибка создания бакетов: %w", err)
	}

	log.Println("База данных успешно инициализирована")
	return nil
}

// createBuckets создает необходимые бакеты
func (dm *DBManager) createBuckets() error {
	return dm.db.Update(func(tx *bbolt.Tx) error {
		buckets := []string{MessagesBucket, PeersBucket, MetadataBucket}

		for _, bucketName := range buckets {
			if _, err := tx.CreateBucketIfNotExists([]byte(bucketName)); err != nil {
				return fmt.Errorf("ошибка создания бакета %s: %w", bucketName, err)
			}
		}

		return nil
	})
}

// Close закрывает базу данных
func (dm *DBManager) Close() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	if dm.db != nil {
		if err := dm.db.Close(); err != nil {
			return fmt.Errorf("ошибка закрытия базы данных: %w", err)
		}
		dm.db = nil
		log.Println("База данных закрыта")
	}
	return nil
}

// IsOpen проверяет, открыта ли база данных
func (dm *DBManager) IsOpen() bool {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.db != nil
}

// generateMessageID генерирует уникальный ID для сообщения
func (dm *DBManager) generateMessageID(sender, recipient string, timestamp int64) string {
	// Очищаем строки
	safeSender := sanitizeForKey(sender)
	safeRecipient := sanitizeForKey(recipient)

	// Безопасно обрезаем строки
	if len(safeSender) > 20 {
		safeSender = safeSender[:20]
	}
	if len(safeRecipient) > 20 {
		safeRecipient = safeRecipient[:20]
	}

	// Создаем ID
	return fmt.Sprintf("%d_%s_%s", timestamp, safeSender, safeRecipient)
}

// sanitizeForKey очищает строку для использования в качестве ключа
func sanitizeForKey(s string) string {
	if len(s) > 50 {
		s = s[:50]
	}
	// Заменяем проблемные символы
	result := make([]byte, 0, len(s))
	for _, b := range []byte(s) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') || b == '-' || b == '_' {
			result = append(result, b)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// SaveMessage сохраняет сообщение в базу данных
func (dm *DBManager) SaveMessage(sender, recipient, content string, timestamp int64, encrypted bool) error {
	if !dm.IsOpen() {
		return fmt.Errorf("база данных не инициализирована")
	}

	// Валидация входных данных
	if sender == "" || recipient == "" {
		return fmt.Errorf("отправитель и получатель не могут быть пустыми")
	}
	if timestamp <= 0 {
		timestamp = time.Now().Unix()
	}

	// Создаем запись сообщения
	message := MessageRecord{
		ID:        dm.generateMessageID(sender, recipient, timestamp),
		Sender:    sender,
		Recipient: recipient,
		Content:   content,
		Timestamp: timestamp,
		Encrypted: encrypted,
		IsRead:    false, // Новое сообщение не прочитано
	}

	// Сериализуем в JSON
	messageJSON, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("ошибка маршаллинга сообщения: %w", err)
	}

	// Сохраняем в базу данных
	err = dm.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(MessagesBucket))
		if b == nil {
			return fmt.Errorf("бакет сообщений не найден")
		}
		return b.Put([]byte(message.ID), messageJSON)
	})

	if err != nil {
		return fmt.Errorf("ошибка сохранения сообщения: %w", err)
	}

	log.Printf("Сообщение сохранено: %s -> %s (ID: %s)", sender, recipient, message.ID)
	return nil
}

// GetMessagesWithPeer возвращает историю сообщений с указанным пиром
func (dm *DBManager) GetMessagesWithPeer(currentUser, peerName string, limit int) ([]MessageRecord, error) {
	if !dm.IsOpen() {
		return nil, fmt.Errorf("база данных не инициализирована")
	}

	if currentUser == "" || peerName == "" {
		return nil, fmt.Errorf("имена пользователей не могут быть пустыми")
	}

	var messages []MessageRecord

	err := dm.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(MessagesBucket))
		if b == nil {
			return fmt.Errorf("бакет сообщений не найден")
		}

		return b.ForEach(func(k, v []byte) error {
			var msg MessageRecord
			if err := json.Unmarshal(v, &msg); err != nil {
				log.Printf("Ошибка десериализации сообщения %s: %v", string(k), err)
				return nil // Пропускаем поврежденные записи
			}

			// Фильтруем сообщения для данного пира
			if (msg.Sender == peerName && msg.Recipient == currentUser) ||
				(msg.Sender == currentUser && msg.Recipient == peerName) {
				messages = append(messages, msg)
			}

			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("ошибка получения сообщений: %w", err)
	}

	// Сортируем по времени
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp < messages[j].Timestamp
	})

	// Применяем лимит, если указан
	if limit > 0 && len(messages) > limit {
		messages = messages[len(messages)-limit:]
	}

	log.Printf("Получено %d сообщений с пиром %s", len(messages), peerName)
	return messages, nil
}

// SavePeer сохраняет информацию о пире в базу данных
func (dm *DBManager) SavePeer(name, address string, publicKey *rsa.PublicKey, status string) error {
	if !dm.IsOpen() {
		return fmt.Errorf("база данных не инициализирована")
	}

	if name == "" || address == "" {
		return fmt.Errorf("имя и адрес пира не могут быть пустыми")
	}

	// Сериализуем публичный ключ в PEM
	var pubKeyPEM string
	if publicKey != nil && dm.crypto != nil {
		// Используем улучшенный метод из CryptoManager
		var err error
		pubKeyPEM, err = dm.crypto.GetPublicKeyPEM()
		if err != nil {
			return fmt.Errorf("ошибка получения публичного ключа: %w", err)
		}
	}

	// Создаем запись пира
	peerRecord := PeerRecord{
		Name:      name,
		Address:   address,
		PublicKey: pubKeyPEM,
		LastSeen:  time.Now().Unix(),
		Status:    status,
	}

	// Сериализуем в JSON
	peerJSON, err := json.Marshal(peerRecord)
	if err != nil {
		return fmt.Errorf("ошибка маршаллинга информации о пире: %w", err)
	}

	// Сохраняем в базу данных
	err = dm.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(PeersBucket))
		if b == nil {
			return fmt.Errorf("бакет пиров не найден")
		}
		return b.Put([]byte(name), peerJSON)
	})

	if err != nil {
		return fmt.Errorf("ошибка сохранения пира: %w", err)
	}

	log.Printf("Информация о пире %s сохранена", name)
	return nil
}

// LoadPeers загружает всех сохраненных пиров из базы данных
func (dm *DBManager) LoadPeers() (map[string]PeerRecord, error) {
	if !dm.IsOpen() {
		return nil, fmt.Errorf("база данных не инициализирована")
	}

	peers := make(map[string]PeerRecord)

	err := dm.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(PeersBucket))
		if b == nil {
			return fmt.Errorf("бакет пиров не найден")
		}

		return b.ForEach(func(k, v []byte) error {
			var peerRecord PeerRecord
			if err := json.Unmarshal(v, &peerRecord); err != nil {
				log.Printf("Ошибка десериализации пира %s: %v", string(k), err)
				return nil // Пропускаем поврежденные записи
			}

			peers[peerRecord.Address] = peerRecord
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки пиров: %w", err)
	}

	log.Printf("Загружено %d пиров из базы данных", len(peers))
	return peers, nil
}

// GetPeer получает информацию о конкретном пире
func (dm *DBManager) GetPeer(name string) (*PeerRecord, error) {
	if !dm.IsOpen() {
		return nil, fmt.Errorf("база данных не инициализирована")
	}

	var peerRecord PeerRecord
	found := false

	err := dm.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(PeersBucket))
		if b == nil {
			return fmt.Errorf("бакет пиров не найден")
		}

		v := b.Get([]byte(name))
		if v == nil {
			return nil // Пир не найден
		}

		if err := json.Unmarshal(v, &peerRecord); err != nil {
			return fmt.Errorf("ошибка десериализации пира: %w", err)
		}

		found = true
		return nil
	})

	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("пир %s не найден", name)
	}

	return &peerRecord, nil
}

// DeletePeer удаляет пира из базы данных
func (dm *DBManager) DeletePeer(name string) error {
	if !dm.IsOpen() {
		return fmt.Errorf("база данных не инициализирована")
	}

	err := dm.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(PeersBucket))
		if b == nil {
			return fmt.Errorf("бакет пиров не найден")
		}
		return b.Delete([]byte(name))
	})

	if err != nil {
		return fmt.Errorf("ошибка удаления пира: %w", err)
	}

	log.Printf("Пир %s удален из базы данных", name)
	return nil
}

// GetStats возвращает статистику базы данных
func (dm *DBManager) GetStats() (map[string]interface{}, error) {
	if !dm.IsOpen() {
		return nil, fmt.Errorf("база данных не инициализирована")
	}

	stats := make(map[string]interface{})

	err := dm.db.View(func(tx *bbolt.Tx) error {
		// Статистика сообщений
		messagesBucket := tx.Bucket([]byte(MessagesBucket))
		if messagesBucket != nil {
			msgStats := messagesBucket.Stats()
			stats["messages_count"] = msgStats.KeyN
		}

		// Статистика пиров
		peersBucket := tx.Bucket([]byte(PeersBucket))
		if peersBucket != nil {
			peerStats := peersBucket.Stats()
			stats["peers_count"] = peerStats.KeyN
		}

		// Общая статистика БД
		stats["db_size"] = tx.Size()

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("ошибка получения статистики: %w", err)
	}

	return stats, nil
}

// Backup создает резервную копию базы данных
func (dm *DBManager) Backup(backupPath string) error {
	if !dm.IsOpen() {
		return fmt.Errorf("база данных не инициализирована")
	}

	// Создаем директорию для бэкапа
	backupDir := filepath.Dir(backupPath)
	if err := os.MkdirAll(backupDir, DBDirMode); err != nil {
		return fmt.Errorf("ошибка создания директории для бэкапа: %w", err)
	}

	// Создаем файл бэкапа
	backupFile, err := os.Create(backupPath)
	if err != nil {
		return fmt.Errorf("ошибка создания файла бэкапа: %w", err)
	}
	defer backupFile.Close()

	// Выполняем бэкап
	err = dm.db.View(func(tx *bbolt.Tx) error {
		_, err := tx.WriteTo(backupFile)
		return err
	})

	if err != nil {
		return fmt.Errorf("ошибка создания бэкапа: %w", err)
	}

	log.Printf("Бэкап базы данных создан: %s", backupPath)
	return nil
}

// WithTimeout выполняет операцию с таймаутом
func (dm *DBManager) WithTimeout(ctx context.Context, operation func() error) error {
	done := make(chan error, 1)

	go func() {
		done <- operation()
	}()

	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetNewMessages получает новые сообщения после указанного timestamp
func (dm *DBManager) GetNewMessages(username string, peer string, since int64) ([]MessageRecord, error) {
	if !dm.IsOpen() {
		return nil, fmt.Errorf("база данных не инициализирована")
	}

	var messages []MessageRecord
	err := dm.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(MessagesBucket))
		if b == nil {
			return fmt.Errorf("бакет сообщений не найден")
		}

		return b.ForEach(func(k, v []byte) error {
			var msg MessageRecord
			if err := json.Unmarshal(v, &msg); err != nil {
				log.Printf("Ошибка десериализации сообщения: %v", err)
				return nil // Пропускаем поврежденные записи
			}

			// Фильтруем сообщения для данного пира после указанного timestamp
			if msg.Timestamp > since &&
				((msg.Sender == peer && msg.Recipient == username) ||
					(msg.Sender == username && msg.Recipient == peer)) {
				messages = append(messages, msg)
			}
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("ошибка получения новых сообщений: %v", err)
	}

	// Сортируем сообщения по времени
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp < messages[j].Timestamp
	})

	return messages, nil
}

// GetMessageHistory получает всю историю сообщений с указанным пиром
func (dm *DBManager) GetMessageHistory(username string, peer string) ([]MessageRecord, error) {
	if !dm.IsOpen() {
		return nil, fmt.Errorf("база данных не инициализирована")
	}

	var messages []MessageRecord
	err := dm.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(MessagesBucket))
		if b == nil {
			return fmt.Errorf("бакет сообщений не найден")
		}

		return b.ForEach(func(k, v []byte) error {
			var msg MessageRecord
			if err := json.Unmarshal(v, &msg); err != nil {
				log.Printf("Ошибка десериализации сообщения: %v", err)
				return nil // Пропускаем поврежденные записи
			}

			// Фильтруем сообщения для данного пира
			if (msg.Sender == peer && msg.Recipient == username) ||
				(msg.Sender == username && msg.Recipient == peer) {
				messages = append(messages, msg)
			}
			return nil
		})
	})

	if err != nil {
		return nil, fmt.Errorf("ошибка получения истории сообщений: %v", err)
	}

	// Сортируем сообщения по времени
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Timestamp < messages[j].Timestamp
	})

	return messages, nil
}

// MarkMessageAsRead помечает сообщение как прочитанное
func (dm *DBManager) MarkMessageAsRead(messageID string) error {
	if !dm.IsOpen() {
		return fmt.Errorf("база данных не инициализирована")
	}

	return dm.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(MessagesBucket))
		if b == nil {
			return fmt.Errorf("бакет сообщений не найден")
		}

		// Получаем сообщение
		data := b.Get([]byte(messageID))
		if data == nil {
			return fmt.Errorf("сообщение не найдено")
		}

		var message MessageRecord
		if err := json.Unmarshal(data, &message); err != nil {
			return fmt.Errorf("ошибка десериализации сообщения: %w", err)
		}

		// Помечаем как прочитанное
		message.IsRead = true

		// Сохраняем обновленное сообщение
		messageJSON, err := json.Marshal(message)
		if err != nil {
			return fmt.Errorf("ошибка маршаллинга сообщения: %w", err)
		}

		return b.Put([]byte(messageID), messageJSON)
	})
}

// Пример использования:
/*
func main() {
	// Инициализация криптографии
	crypto := NewCryptoManager("keys", "private.pem", "public.pem")
	if err := crypto.InitKeys(); err != nil {
		log.Fatalf("Ошибка инициализации криптографии: %v", err)
	}

	// Инициализация базы данных
	dbPath := filepath.Join(DBDir, DBFile)
	dbManager := NewDBManager(dbPath, crypto)

	if err := dbManager.Init(); err != nil {
		log.Fatalf("Ошибка инициализации базы данных: %v", err)
	}
	defer dbManager.Close()

	// Сохранение сообщения
	timestamp := time.Now().Unix()
	err := dbManager.SaveMessage("alice", "bob", "Привет!", timestamp, false)
	if err != nil {
		log.Printf("Ошибка сохранения сообщения: %v", err)
	}

	// Получение сообщений
	messages, err := dbManager.GetMessagesWithPeer("alice", "bob", 10)
	if err != nil {
		log.Printf("Ошибка получения сообщений: %v", err)
	} else {
		fmt.Printf("Найдено %d сообщений\n", len(messages))
	}

	// Получение статистики
	stats, err := dbManager.GetStats()
	if err != nil {
		log.Printf("Ошибка получения статистики: %v", err)
	} else {
		fmt.Printf("Статистика БД: %+v\n", stats)
	}
}
*/
