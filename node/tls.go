package node

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

// certRenewalLoop checks cert expiry hourly and auto-renews when <30 days remain.
func (n *Node) certRenewalLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.checkCertRenewal()
		}
	}
}

func (n *Node) checkCertRenewal() {
	cert := n.identity.TLSCert
	if len(cert.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return
	}
	remaining := time.Until(leaf.NotAfter)
	if remaining > 30*24*time.Hour {
		return
	}
	Infof("cert: %s remaining — initiating renewal", remaining.Round(time.Hour))
	if err := n.renewCert(); err != nil {
		Warnf("cert: renewal failed: %v", err)
	}
}

func (n *Node) renewCert() error {
	req := JoinRequest{
		PublicKey: ed25519.PublicKey(n.identity.PublicKey),
		Token:     n.cfg.Join.Token,
	}
	resp := n.resolveJoin(req)
	if resp.Error != "" {
		return fmt.Errorf("CA rejected renewal: %s", resp.Error)
	}
	if err := StoreJoinResult(n.cfg.Node.DataDir, resp); err != nil {
		return err
	}
	Infof("cert: renewed successfully")
	return n.ReloadIdentity()
}

// ReloadIdentity reloads the identity from disk (after a successful join).
func (n *Node) ReloadIdentity() error {
	id, err := LoadOrCreateIdentity(n.cfg.Node.DataDir)
	if err != nil {
		return err
	}
	n.identity = id
	Infof("identity reloaded: joined=%v", id.Joined)
	return nil
}

func (n *Node) serverTLSConfig() *tls.Config {
	cfg := &tls.Config{
		// Dynamic cert: picks up renewed certs without restart.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &n.identity.TLSCert, nil
		},
	}
	if n.ca != nil {
		cfg.ClientAuth = tls.RequestClientCert
		cfg.ClientCAs = n.ca.Pool
	} else if n.identity.CAPool != nil {
		cfg.ClientAuth = tls.RequestClientCert
		cfg.ClientCAs = n.identity.CAPool
	}
	return cfg
}

func (n *Node) clientTLSConfig() *tls.Config {
	getCert := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return &n.identity.TLSCert, nil
	}
	if n.identity.CAPool != nil {
		cfg := ClientTLSConfig(n.identity.TLSCert, n.identity.CAPool)
		cfg.GetClientCertificate = getCert
		return cfg
	}
	if n.ca != nil {
		cfg := ClientTLSConfig(n.identity.TLSCert, n.ca.Pool)
		cfg.GetClientCertificate = getCert
		return cfg
	}
	return &tls.Config{
		GetClientCertificate: getCert,
		InsecureSkipVerify:   true,
	}
}
