package shouqianbapoc

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestCallbackHandler(t *testing.T) {
	// 读取私钥文件
	privateKeyPEM, err := os.ReadFile("private.pem")
	if err != nil {
		t.Fatalf("Failed to read private key: %v", err)
	}

	// 解析私钥
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	publicKeyPEM, err := os.ReadFile("public.pem")
	if err != nil {
		t.Fatalf("Failed to read public key: %v", err)
	}

	handler, err := NewCallbackHandler(string(publicKeyPEM))
	if err != nil {
		t.Fatalf("Failed to create handler: %v", err)
	}

	testCases := []struct {
		name           string
		payload        map[string]interface{}
		signBody       bool
		modifySign     bool
		expectedStatus int
	}{
		{
			name: "Valid notification",
			payload: map[string]interface{}{
				"order_id":    "TEST123456",
				"amount":      10000,
				"status":      "PAID",
				"paid_time":   "2024-03-20T10:00:00Z",
				"terminal_sn": "TEST-TERMINAL",
			},
			signBody:       true,
			modifySign:     false,
			expectedStatus: http.StatusOK,
		},
		{
			name: "Invalid signature",
			payload: map[string]interface{}{
				"order_id": "TEST123456",
				"amount":   10000,
			},
			signBody:       true,
			modifySign:     true,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "Missing signature",
			payload: map[string]interface{}{
				"order_id": "TEST123456",
				"amount":   10000,
			},
			signBody:       false,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 将 payload 转换为 JSON
			body, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatalf("Failed to marshal payload: %v", err)
			}

			// 创建请求
			req := httptest.NewRequest(http.MethodPost, "/callback", bytes.NewReader(body))

			if tc.signBody {
				// 计算签名
				hashed := sha256.Sum256(body)
				signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA256, hashed[:])
				if err != nil {
					t.Fatalf("Failed to sign message: %v", err)
				}

				// 转换为十六进制字符串
				signHex := hex.EncodeToString(signature)
				if tc.modifySign {
					signHex = signHex + "invalid"
				}
				req.Header.Set("Authorization", signHex)
			}

			// 记录响应
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, w.Code)
			}

			if tc.expectedStatus == http.StatusOK {
				t.Logf("Response: %v", w.Body.String())
			}
		})
	}
}

func TestNewCallbackHandler(t *testing.T) {
	publicKeyPEM, err := os.ReadFile("public.pem")
	if err != nil {
		t.Fatalf("Failed to read public key: %v", err)
	}

	testCases := []struct {
		name        string
		publicKey   string
		expectError bool
	}{
		{
			name:        "Valid public key",
			publicKey:   string(publicKeyPEM),
			expectError: false,
		},
		{
			name:        "Invalid public key",
			publicKey:   "invalid key data",
			expectError: true,
		},
		{
			name:        "Empty public key",
			publicKey:   "",
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			handler, err := NewCallbackHandler(tc.publicKey)
			if tc.expectError {
				if err == nil {
					t.Error("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if handler == nil {
					t.Error("Handler is nil")
				}
			}
		})
	}
}
