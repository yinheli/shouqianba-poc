package shouqianbapoc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
)

// CallbackHandler 处理收钱吧回调请求的 HTTP handler
type CallbackHandler struct {
	PublicKey *rsa.PublicKey
}

// NewCallbackHandler 创建新的回调处理器
func NewCallbackHandler(publicKeyPEM string) (*CallbackHandler, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}

	return &CallbackHandler{PublicKey: publicKey}, nil
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. 获取签名
	sign := r.Header.Get("Authorization")
	if sign == "" {
		http.Error(w, "missing signature", http.StatusBadRequest)
		return
	}

	// 2. 读取请求体
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	// 3. 验证签名
	valid, err := h.VerifySignature(body, sign)
	if err != nil {
		http.Error(w, "signature verification failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !valid {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("success"))
}

// VerifySignature 验证签名
func (h *CallbackHandler) VerifySignature(message []byte, signature string) (bool, error) {
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}

	hashed := sha256.Sum256(message)
	err = rsa.VerifyPKCS1v15(h.PublicKey, crypto.SHA256, hashed[:], sig)
	if err != nil {
		return false, nil
	}

	return true, nil
}
