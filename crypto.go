package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
)

const (
	// RSA key size - можно увеличить до 4096 для большей безопасности
	RSAKeySize = 2048
	// Права доступа для файлов ключей
	KeyFileMode = 0600
	// Права доступа для директории ключей
	KeyDirMode = 0700
)

// CryptoManager управляет RSA ключами
type CryptoManager struct {
	keyDir         string
	privateKeyFile string
	publicKeyFile  string
	privateKey     *rsa.PrivateKey
}

// NewCryptoManager создает новый менеджер криптографии
func NewCryptoManager(keyDir, privateKeyFile, publicKeyFile string) *CryptoManager {
	return &CryptoManager{
		keyDir:         keyDir,
		privateKeyFile: privateKeyFile,
		publicKeyFile:  publicKeyFile,
	}
}

// InitKeys инициализирует RSA ключи: загружает существующие или создает новые
func (cm *CryptoManager) InitKeys() error {
	log.Println("Инициализация ключей шифрования")

	// Создаем директорию для ключей, если она не существует
	if err := os.MkdirAll(cm.keyDir, KeyDirMode); err != nil {
		return fmt.Errorf("не удалось создать директорию для ключей: %w", err)
	}

	privPath := filepath.Join(cm.keyDir, cm.privateKeyFile)
	pubPath := filepath.Join(cm.keyDir, cm.publicKeyFile)

	// Проверяем существование ключей
	privExists := fileExists(privPath)
	pubExists := fileExists(pubPath)

	if !privExists || !pubExists {
		log.Println("Ключи не найдены, генерируем новую пару ключей")
		if err := cm.generateRSAKeys(privPath, pubPath); err != nil {
			return fmt.Errorf("ошибка генерации ключей: %w", err)
		}
		fmt.Println("RSA-ключи сгенерированы.")
		log.Println("RSA-ключи успешно сгенерированы")
	} else {
		log.Println("Загружаем существующие ключи")
	}

	// Загружаем приватный ключ
	if err := cm.loadPrivateKey(privPath); err != nil {
		return fmt.Errorf("ошибка загрузки приватного ключа: %w", err)
	}

	log.Println("Ключи успешно инициализированы")
	return nil
}

// loadPrivateKey загружает приватный ключ из файла
func (cm *CryptoManager) loadPrivateKey(privPath string) error {
	privKeyData, err := os.ReadFile(privPath)
	if err != nil {
		return fmt.Errorf("ошибка чтения файла приватного ключа: %w", err)
	}

	block, _ := pem.Decode(privKeyData)
	if block == nil {
		return fmt.Errorf("не удалось декодировать PEM блок")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("ошибка парсинга приватного ключа: %w", err)
	}

	cm.privateKey = privateKey
	return nil
}

// generateRSAKeys генерирует новую пару RSA ключей и сохраняет их в файлы
func (cm *CryptoManager) generateRSAKeys(privPath, pubPath string) error {
	log.Printf("Начало генерации RSA ключей (%d бит)", RSAKeySize)

	// Генерация приватного ключа
	privKey, err := rsa.GenerateKey(rand.Reader, RSAKeySize)
	if err != nil {
		return fmt.Errorf("ошибка генерации ключа: %w", err)
	}

	// Валидация ключа
	if err := privKey.Validate(); err != nil {
		return fmt.Errorf("сгенерированный ключ не прошел валидацию: %w", err)
	}

	// Сохранение приватного ключа в PEM
	if err := cm.savePrivateKey(privPath, privKey); err != nil {
		return fmt.Errorf("ошибка сохранения приватного ключа: %w", err)
	}

	// Сохранение публичного ключа в PEM
	if err := cm.savePublicKey(pubPath, &privKey.PublicKey); err != nil {
		return fmt.Errorf("ошибка сохранения публичного ключа: %w", err)
	}

	log.Println("RSA ключи успешно сгенерированы")
	return nil
}

// savePrivateKey сохраняет приватный ключ в файл
func (cm *CryptoManager) savePrivateKey(path string, privKey *rsa.PrivateKey) error {
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}
	return cm.writePemFile(path, privBlock)
}

// savePublicKey сохраняет публичный ключ в файл
func (cm *CryptoManager) savePublicKey(path string, pubKey *rsa.PublicKey) error {
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("ошибка маршаллинга публичного ключа: %w", err)
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}
	return cm.writePemFile(path, pubBlock)
}

// writePemFile записывает PEM блок в файл с безопасными правами доступа
func (cm *CryptoManager) writePemFile(path string, block *pem.Block) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, KeyFileMode)
	if err != nil {
		return fmt.Errorf("не удалось создать файл %s: %w", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, block); err != nil {
		return fmt.Errorf("ошибка записи PEM данных в файл %s: %w", path, err)
	}

	return nil
}

// GetPublicKey возвращает публичный ключ
func (cm *CryptoManager) GetPublicKey() *rsa.PublicKey {
	if cm.privateKey == nil {
		return nil
	}
	return &cm.privateKey.PublicKey
}

// GetPrivateKey возвращает приватный ключ
func (cm *CryptoManager) GetPrivateKey() *rsa.PrivateKey {
	return cm.privateKey
}

// GetPublicKeyPEM возвращает публичный ключ в формате PEM
func (cm *CryptoManager) GetPublicKeyPEM() (string, error) {
	if cm.privateKey == nil {
		return "", fmt.Errorf("приватный ключ не инициализирован")
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&cm.privateKey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("ошибка маршаллинга публичного ключа: %w", err)
	}

	pubBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}

	pemData := pem.EncodeToMemory(pubBlock)
	return string(pemData), nil
}

// ParsePublicKeyPEM парсит публичный ключ из PEM формата
func ParsePublicKeyPEM(pemData string) (*rsa.PublicKey, error) {
	if pemData == "" {
		return nil, fmt.Errorf("пустые PEM данные")
	}

	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM блок публичного ключа")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка парсинга публичного ключа: %w", err)
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ключ не является RSA публичным ключом")
	}

	return pubKey, nil
}

// EncryptWithPublicKey шифрует данные с использованием публичного ключа
func (cm *CryptoManager) EncryptWithPublicKey(data []byte, pubKey *rsa.PublicKey) ([]byte, error) {
	if pubKey == nil {
		return nil, fmt.Errorf("публичный ключ не может быть nil")
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	if err != nil {
		return nil, fmt.Errorf("ошибка шифрования: %w", err)
	}

	return encrypted, nil
}

// DecryptWithPrivateKey расшифровывает данные с использованием приватного ключа
func (cm *CryptoManager) DecryptWithPrivateKey(encryptedData []byte) ([]byte, error) {
	if cm.privateKey == nil {
		return nil, fmt.Errorf("приватный ключ не инициализирован")
	}

	decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, cm.privateKey, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %w", err)
	}

	return decrypted, nil
}

// fileExists проверяет существование файла
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// SecureWipe безопасно очищает память (базовая реализация)
func SecureWipe(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// GenerateRandomBytes генерирует криптографически стойкие случайные байты
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, fmt.Errorf("ошибка генерации случайных байт: %w", err)
	}
	return bytes, nil
}

// Пример использования:
/*
func main() {
	manager := NewCryptoManager("keys", "private.pem", "public.pem")

	if err := manager.InitKeys(); err != nil {
		log.Fatalf("Ошибка инициализации ключей: %v", err)
	}

	// Получение публичного ключа в PEM формате
	pubKeyPEM, err := manager.GetPublicKeyPEM()
	if err != nil {
		log.Fatalf("Ошибка получения публичного ключа: %v", err)
	}

	fmt.Println("Публичный ключ:")
	fmt.Println(pubKeyPEM)

	// Парсинг публичного ключа из PEM
	pubKey, err := ParsePublicKeyPEM(pubKeyPEM)
	if err != nil {
		log.Fatalf("Ошибка парсинга публичного ключа: %v", err)
	}

	// Шифрование данных
	data := []byte("Секретное сообщение")
	encrypted, err := manager.EncryptWithPublicKey(data, pubKey)
	if err != nil {
		log.Fatalf("Ошибка шифрования: %v", err)
	}

	// Расшифровка данных
	decrypted, err := manager.DecryptWithPrivateKey(encrypted)
	if err != nil {
		log.Fatalf("Ошибка расшифровки: %v", err)
	}

	fmt.Printf("Исходные данные: %s\n", data)
	fmt.Printf("Расшифрованные данные: %s\n", decrypted)
}
*/
