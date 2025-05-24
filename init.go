package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"path/filepath"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

var (
	dbEnabled     bool
	cryptoManager *CryptoManager
	dbManager     *DBManager
	logLevel      = LogLevelInfo // уровень логирования по умолчанию
)

// Определяем уровни логирования
const (
	LogLevelDebug = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// initKeys инициализирует криптографические ключи
func initKeys() error {
	cryptoManager = NewCryptoManager(keyDir, privateKeyFile, publicKeyFile)
	if err := cryptoManager.InitKeys(); err != nil {
		return fmt.Errorf("ошибка инициализации ключей: %v", err)
	}
	privateKey = cryptoManager.GetPrivateKey()
	return nil
}

// initDB инициализирует базу данных
func initDB() error {
	dbPath := filepath.Join(DBDir, DBFile)
	dbManager = NewDBManager(dbPath, cryptoManager)
	if err := dbManager.Init(); err != nil {
		return fmt.Errorf("ошибка инициализации базы данных: %v", err)
	}
	dbEnabled = true
	return nil
}

// closeDB закрывает соединение с базой данных
func closeDB() {
	if dbEnabled && dbManager != nil {
		dbManager.Close()
	}
}

// setLogLevel устанавливает уровень логирования по строке
func setLogLevel(level string) {
	switch level {
	case "debug":
		logLevel = LogLevelDebug
	case "info":
		logLevel = LogLevelInfo
	case "warn":
		logLevel = LogLevelWarn
	case "error":
		logLevel = LogLevelError
	default:
		logLevel = LogLevelInfo
	}
}

// Вспомогательные функции для логирования с уровнями
func LogDebug(format string, v ...interface{}) {
	if logLevel <= LogLevelDebug {
		log.Printf("[DEBUG] "+format, v...)
	}
}
func LogInfo(format string, v ...interface{}) {
	if logLevel <= LogLevelInfo {
		log.Printf("[INFO] "+format, v...)
	}
}
func LogWarn(format string, v ...interface{}) {
	if logLevel <= LogLevelWarn {
		log.Printf("[WARN] "+format, v...)
	}
}
func LogError(format string, v ...interface{}) {
	if logLevel <= LogLevelError {
		log.Printf("[ERROR] "+format, v...)
	}
}

// setupLogging настраивает логирование с ротацией через lumberjack
func setupLogging() error {
	logger := &lumberjack.Logger{
		Filename:   "swagnet.log",
		MaxSize:    5, // мегабайт
		MaxBackups: 3,
		MaxAge:     30, // дней
		Compress:   true,
	}
	log.SetOutput(logger)
	return nil
}

// getPublicKeyPEM возвращает публичный ключ в формате PEM
func getPublicKeyPEM() string {
	if cryptoManager == nil {
		return ""
	}
	pem, err := cryptoManager.GetPublicKeyPEM()
	if err != nil {
		log.Printf("Ошибка получения публичного ключа PEM: %v", err)
		return ""
	}
	return pem
}

// parsePublicKeyPEM парсит публичный ключ из формата PEM
func parsePublicKeyPEM(pemData string) *rsa.PublicKey {
	pubKey, err := ParsePublicKeyPEM(pemData)
	if err != nil {
		log.Printf("Ошибка парсинга публичного ключа PEM: %v", err)
		return nil
	}
	return pubKey
}

// savePeerInfo сохраняет информацию о пире в базу данных
func savePeerInfo(peer Peer) error {
	if !dbEnabled || dbManager == nil {
		return fmt.Errorf("база данных не инициализирована")
	}
	return dbManager.SavePeer(peer.Name, peer.Address, peer.PublicKey, "online")
}

// saveMessage сохраняет сообщение в базу данных
func saveMessage(sender string, recipient string, content string, timestamp int64) error {
	if !dbEnabled || dbManager == nil {
		return fmt.Errorf("база данных не инициализирована")
	}
	return dbManager.SaveMessage(sender, recipient, content, timestamp, false)
}

// loadPeers загружает известных пиров из базы данных
func loadPeers() error {
	if !dbEnabled || dbManager == nil {
		return fmt.Errorf("база данных не инициализирована")
	}
	loadedPeers, err := dbManager.LoadPeers()
	if err != nil {
		return err
	}

	peersMutex.Lock()
	defer peersMutex.Unlock()

	for _, peer := range loadedPeers {
		pubKey, _ := ParsePublicKeyPEM(peer.PublicKey)
		if pubKey != nil {
			peers[peer.Address] = Peer{
				Address:   peer.Address,
				Name:      peer.Name,
				PublicKey: pubKey,
				LastSeen:  time.Unix(peer.LastSeen, 0),
				IsOnline:  false,
			}
		}
	}
	return nil
}

// getMessagesWithPeer загружает историю сообщений с конкретным пиром
func getMessagesWithPeer(peer string) ([]MessageRecord, error) {
	if !dbEnabled || dbManager == nil {
		return nil, fmt.Errorf("база данных не инициализирована")
	}
	return dbManager.GetMessageHistory(username, peer)
}
