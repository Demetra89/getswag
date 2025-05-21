package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// initKeys инициализирует RSA ключи: загружает существующие или создает новые
func initKeys() {
	log.Println("Инициализация ключей шифрования")

	// Создаем директорию для ключей, если она не существует
	os.MkdirAll(keyDir, 0700)
	privPath := filepath.Join(keyDir, privateKeyFile)
	pubPath := filepath.Join(keyDir, publicKeyFile)

	if !fileExists(privPath) || !fileExists(pubPath) {
		log.Println("Ключи не найдены, генерируем новую пару ключей")
		if err := generateRSAKeys(privPath, pubPath); err != nil {
			log.Fatalf("Ошибка генерации ключей: %v", err)
			os.Exit(1)
		}
		fmt.Println("RSA-ключи сгенерированы.")
		log.Println("RSA-ключи успешно сгенерированы")
	} else {
		log.Println("Загружаем существующие ключи")
	}

	// Загружаем приватный ключ
	privKeyData, err := ioutil.ReadFile(privPath)
	if err != nil {
		log.Fatalf("Ошибка чтения приватного ключа: %v", err)
		fmt.Println("Ошибка чтения приватного ключа:", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(privKeyData)
	if block == nil {
		log.Fatal("Ошибка декодирования PEM блока")
		fmt.Println("Ошибка декодирования PEM блока")
		os.Exit(1)
	}

	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Ошибка парсинга приватного ключа: %v", err)
		fmt.Println("Ошибка парсинга приватного ключа:", err)
		os.Exit(1)
	}

	log.Println("Ключи успешно инициализированы")
}

// generateRSAKeys генерирует новую пару RSA ключей и сохраняет их в файлы
func generateRSAKeys(privPath, pubPath string) error {
	log.Println("Начало генерации RSA ключей (2048 бит)")

	// Генерация приватного ключа
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Ошибка генерации ключа: %v", err)
		return err
	}

	// Сохранение приватного ключа в PEM
	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	if err := writePemFile(privPath, privBlock); err != nil {
		log.Printf("Ошибка записи приватного ключа: %v", err)
		return err
	}

	// Сохранение публичного ключа в PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		log.Printf("Ошибка маршаллинга публичного ключа: %v", err)
		return err
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	if err := writePemFile(pubPath, pubBlock); err != nil {
		log.Printf("Ошибка записи публичного ключа: %v", err)
		return err
	}

	log.Println("RSA ключи успешно сгенерированы")
	return nil
}

// writePemFile записывает PEM блок в файл
func writePemFile(path string, block *pem.Block) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, block)
}

// getPublicKeyPEM возвращает публичный ключ в формате PEM
func getPublicKeyPEM() string {
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Printf("Ошибка маршаллинга публичного ключа: %v", err)
		return ""
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}
	pemData := pem.EncodeToMemory(pubBlock)
	return string(pemData)
}

// parsePublicKeyPEM парсит публичный ключ из PEM формата
func parsePublicKeyPEM(pemData string) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		log.Println("Ошибка декодирования PEM блока публичного ключа")
		return nil
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Printf("Ошибка парсинга публичного ключа: %v", err)
		return nil
	}

	pubKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		log.Println("Интерфейс не является публичным RSA ключом")
		return nil
	}

	return pubKey
}
