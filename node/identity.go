package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type Identity struct {
	NodeID     string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	TLSCert    tls.Certificate
	CAPool     *x509.CertPool // nil until joined; then used for mTLS peer verification
	Joined     bool           // true once the node has a CA-signed cert
}

func LoadOrCreateIdentity(dir string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "identity.key")
	certPath := filepath.Join(dir, "identity.crt")

	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey

	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		pub, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			return nil, err
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return nil, err
		}
	} else {
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(keyPEM)
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		priv = key.(ed25519.PrivateKey)
		pub = priv.Public().(ed25519.PublicKey)
	}

	nodeID := nodeIDFromKey(pub)

	var tlsCert tls.Certificate
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		certDER, err := selfSignedCert(pub, priv, nodeID)
		if err != nil {
			return nil, err
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
			return nil, err
		}
		keyPEM, _ := os.ReadFile(keyPath)
		tlsCert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
	} else {
		keyPEM, _ := os.ReadFile(keyPath)
		certPEM, _ := os.ReadFile(certPath)
		var err error
		tlsCert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
	}

	id := &Identity{
		NodeID:     nodeID,
		PublicKey:  pub,
		PrivateKey: priv,
		TLSCert:    tlsCert,
	}

	// If a CA cert exists on disk (written after a successful join), load it.
	caCertPath := filepath.Join(dir, "ca.crt")
	if caCertPEM, err := os.ReadFile(caCertPath); err == nil {
		pool, err := LoadCAPool(caCertPEM)
		if err == nil {
			id.CAPool = pool
			id.Joined = true
		}
	}

	return id, nil
}

// StoreJoinResult persists the CA cert and CA-signed node cert returned by the join flow.
func StoreJoinResult(dir string, resp JoinResponse) error {
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte(resp.CACert), 0644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "identity.crt"), []byte(resp.SignedCert), 0644)
}

// LoadNodePubKey loads an Ed25519 public key from a PEM file.
// Useful for the operator authorize flow.
func LoadNodePubKey(path string) (ed25519.PublicKey, error) {
	pemData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return pub.(ed25519.PublicKey), nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return key.(ed25519.PrivateKey).Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}
}

// SignIdentityFromKeyFile loads a node's identity.key and signs a cert using the given CA.
// Returns the JoinResponse (containing signed cert + CA cert PEM) and the node ID.
// Used for offline signing when the CA is behind NAT and unreachable by the new node.
func SignIdentityFromKeyFile(keyPath string, ca *CA) (JoinResponse, string, error) {
	pub, err := LoadNodePubKey(keyPath)
	if err != nil {
		return JoinResponse{}, "", fmt.Errorf("load key: %w", err)
	}
	nodeID := nodeIDFromKey(pub)
	resp, err := ca.SignIdentity(pub, nodeID)
	if err != nil {
		return JoinResponse{}, "", err
	}
	return resp, nodeID, nil
}

func nodeIDFromKey(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:8]) // 16-char ID, readable
}

func selfSignedCert(pub ed25519.PublicKey, priv ed25519.PrivateKey, nodeID string) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: nodeID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
}
