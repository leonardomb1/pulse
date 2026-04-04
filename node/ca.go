package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CA is the certificate authority for the pulse network.
// Only one node runs as CA; all others get their certs signed by it.
type CA struct {
	PrivKey   ed25519.PrivateKey
	Cert      *x509.Certificate
	CertPEM   []byte
	Pool      *x509.CertPool
	JoinToken string    // legacy master token (fallback)
	Audit     *AuditLog // nil if audit logging not configured

	revokedMu  sync.RWMutex
	revokedIDs map[string]struct{}

	tokensMu    sync.RWMutex
	tokens      []JoinToken  // scribe-managed tokens (synced via NetworkConfig)
	OnTokenUsed func(string) // callback when a token is used (wired to scribe)
}

// JoinRequest is sent by a new node to request a signed certificate.
type JoinRequest struct {
	PublicKey []byte `json:"public_key"` // raw ed25519 public key of the joining node
	Token     string `json:"token"`      // shared join token
}

// JoinResponse is returned by the CA (or proxied back through the mesh).
type JoinResponse struct {
	CACert     string `json:"ca_cert"`     // PEM of the CA certificate
	SignedCert string `json:"signed_cert"` // PEM of the node's CA-signed certificate
	NodeID     string `json:"node_id"`
	Error      string `json:"error,omitempty"`
}

// InitCA generates a new CA keypair and writes it to dir.
func InitCA(dir string, joinToken string) (*CA, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pulse-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	privBytes, _ := x509.MarshalPKCS8PrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0644); err != nil {
		return nil, err
	}

	cert, _ := x509.ParseCertificate(certDER)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &CA{
		PrivKey:   priv,
		Cert:      cert,
		CertPEM:   certPEM,
		Pool:      pool,
		JoinToken: joinToken,
	}, nil
}

// LoadCA loads an existing CA from disk.
func LoadCA(dir string, joinToken string) (*CA, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyPEM)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv := key.(ed25519.PrivateKey)

	block, _ = pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)

	return &CA{
		PrivKey:   priv,
		Cert:      cert,
		CertPEM:   certPEM,
		Pool:      pool,
		JoinToken: joinToken,
	}, nil
}

// LoadCAPool loads only the CA cert for client nodes (no private key needed).
func LoadCAPool(caCertPEM []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCertPEM) {
		return nil, errors.New("failed to parse CA certificate")
	}
	return pool, nil
}

// HandleJoin validates a join request and returns the signed certificate.
// Authentication is token-based only.
func (ca *CA) HandleJoin(req JoinRequest) JoinResponse {
	nodePubKey := ed25519.PublicKey(req.PublicKey)
	nodeID := nodeIDFromKey(nodePubKey)

	ca.audit(AuditEntry{Op: AuditJoinAttempted, NodeID: nodeID})

	if ca.IsRevoked(nodeID) {
		resp := JoinResponse{Error: "node has been revoked"}
		ca.audit(AuditEntry{Op: AuditJoinFailed, NodeID: nodeID, Error: resp.Error})
		return resp
	}

	matchedToken, err := ca.validateToken(req.Token)
	if err != nil {
		resp := JoinResponse{Error: "invalid join token"}
		ca.audit(AuditEntry{Op: AuditJoinFailed, NodeID: nodeID, Error: resp.Error})
		return resp
	}

	signedDER, err := ca.signNodeCert(nodePubKey, nodeID)
	if err != nil {
		resp := JoinResponse{Error: fmt.Sprintf("signing failed: %v", err)}
		ca.audit(AuditEntry{Op: AuditJoinFailed, NodeID: nodeID, Error: resp.Error})
		return resp
	}

	ca.audit(AuditEntry{Op: AuditCertIssued, NodeID: nodeID})

	// Notify scribe of token usage for use-count tracking.
	if matchedToken != "" && ca.OnTokenUsed != nil {
		ca.OnTokenUsed(matchedToken)
	}

	signedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedDER})
	return JoinResponse{
		CACert:     string(ca.CertPEM),
		SignedCert: string(signedPEM),
		NodeID:     nodeID,
	}
}

// RevokeNode marks nodeID as revoked in the CA's local revocation set and audits it.
// The scribe is responsible for distributing the revocation via NetworkConfig.
func (ca *CA) RevokeNode(nodeID string) {
	ca.revokedMu.Lock()
	if ca.revokedIDs == nil {
		ca.revokedIDs = make(map[string]struct{})
	}
	ca.revokedIDs[nodeID] = struct{}{}
	ca.revokedMu.Unlock()
	ca.audit(AuditEntry{Op: AuditCertRevoked, NodeID: nodeID})
}

// IsRevoked reports whether nodeID has been revoked.
func (ca *CA) IsRevoked(nodeID string) bool {
	ca.revokedMu.RLock()
	defer ca.revokedMu.RUnlock()
	_, ok := ca.revokedIDs[nodeID]
	return ok
}

// SyncTokens updates the CA's local token list from a scribe NetworkConfig.
func (ca *CA) SyncTokens(tokens []JoinToken) {
	ca.tokensMu.Lock()
	defer ca.tokensMu.Unlock()
	ca.tokens = make([]JoinToken, len(tokens))
	copy(ca.tokens, tokens)
}

// validateToken checks the request token against scribe-managed tokens first,
// then falls back to the legacy master token. Returns the matched token value
// (empty for legacy) or an error.
func (ca *CA) validateToken(reqToken string) (matchedValue string, err error) {
	ca.tokensMu.RLock()
	tokens := ca.tokens
	ca.tokensMu.RUnlock()

	reqBytes := []byte(reqToken)
	for _, t := range tokens {
		if !t.IsValid() {
			continue
		}
		if subtle.ConstantTimeCompare(reqBytes, []byte(t.Value)) == 1 {
			return t.Value, nil
		}
	}
	// Fallback: legacy master token.
	if ca.JoinToken != "" && subtle.ConstantTimeCompare(reqBytes, []byte(ca.JoinToken)) == 1 {
		return "", nil
	}
	return "", fmt.Errorf("invalid join token")
}

// SyncRevokedIDs updates the CA's local revocation set from a scribe NetworkConfig.
func (ca *CA) SyncRevokedIDs(ids []string) {
	ca.revokedMu.Lock()
	defer ca.revokedMu.Unlock()
	if ca.revokedIDs == nil {
		ca.revokedIDs = make(map[string]struct{})
	}
	for _, id := range ids {
		ca.revokedIDs[id] = struct{}{}
	}
}

func (ca *CA) audit(e AuditEntry) {
	if ca.Audit != nil {
		ca.Audit.Write(e)
	}
}

func (ca *CA) signNodeCert(nodePubKey ed25519.PublicKey, nodeID string) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: nodeID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour), // 90 days
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	return x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, nodePubKey, ca.PrivKey)
}

// SignIdentity issues a CA-signed certificate for the given node identity.
// Used by the CA node to sign its own cert during first-time initialization,
// so peers can verify it via mTLS using the CA pool.
func (ca *CA) SignIdentity(pub ed25519.PublicKey, nodeID string) (JoinResponse, error) {
	signedDER, err := ca.signNodeCert(pub, nodeID)
	if err != nil {
		return JoinResponse{}, err
	}
	signedPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedDER})
	return JoinResponse{
		CACert:     string(ca.CertPEM),
		SignedCert: string(signedPEM),
		NodeID:     nodeID,
	}, nil
}

// ServerTLSConfig returns a TLS config that enforces mTLS using the CA as trust root.
func (ca *CA) ServerTLSConfig(nodeCert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{nodeCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    ca.Pool,
	}
}

// ClientTLSConfig returns a TLS config that presents the node cert and verifies peers against the CA.
//
// Overlay networks don't use hostname-based certificate verification — peer addresses
// are determined by the gossip table, not DNS. We skip Go's built-in hostname check
// and instead verify the cert chain manually against the CA pool. This is the same
// approach used by WireGuard, Tailscale, and other mesh VPNs.
func ClientTLSConfig(nodeCert tls.Certificate, caPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{nodeCert},
		InsecureSkipVerify: true, // hostname check disabled; chain verified below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("peer sent no certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse peer cert: %w", err)
			}
			// Verify chain against CA pool without hostname matching.
			opts := x509.VerifyOptions{Roots: caPool}
			if _, err := cert.Verify(opts); err != nil {
				return fmt.Errorf("peer cert verification: %w", err)
			}
			return nil
		},
	}
}
