//go:build linux

package node

// Raw netlink helpers for routing (RTM_NEWROUTE/RTM_DELROUTE),
// default interface discovery (RTM_GETROUTE), and nftables masquerade.
// No external dependencies — uses golang.org/x/sys/unix directly.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// netlinkRouteAdd adds a route via raw netlink (no exec needed, works with CAP_NET_ADMIN).
func netlinkRouteAdd(cidr string, ifIndex int) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	ones, _ := ipNet.Mask.Size()
	dst := ip.To4()
	if dst == nil {
		return fmt.Errorf("IPv4 only")
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_ = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})

	// Build RTM_NEWROUTE message.
	msg := make([]byte, 0, 128)
	// nlmsghdr (16 bytes)
	msg = append(msg, 0, 0, 0, 0) // len (fill later)
	msg = appendU16(msg, unix.RTM_NEWROUTE)
	msg = appendU16(msg, unix.NLM_F_REQUEST|unix.NLM_F_CREATE|unix.NLM_F_REPLACE|unix.NLM_F_ACK)
	msg = appendU32(msg, 1) // seq
	msg = appendU32(msg, 0) // pid
	// rtmsg (12 bytes)
	msg = append(msg, unix.AF_INET) // family
	msg = append(msg, byte(ones))   // dst_len
	msg = append(msg, 0)            // src_len
	msg = append(msg, 0)            // tos
	msg = append(msg, unix.RT_TABLE_MAIN)
	msg = append(msg, unix.RTPROT_STATIC)
	msg = append(msg, unix.RT_SCOPE_LINK)
	msg = append(msg, unix.RTN_UNICAST)
	msg = appendU32(msg, 0) // flags
	// RTA_DST
	msg = appendRTA(msg, unix.RTA_DST, dst[:4])
	// RTA_OIF
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(ifIndex))
	msg = appendRTA(msg, unix.RTA_OIF, oif)
	// Fill length.
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))

	return unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

func netlinkRouteDel(cidr string, ifIndex int) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}
	ones, _ := ipNet.Mask.Size()
	dst := ip.To4()
	if dst == nil {
		return
	}

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	_ = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})

	msg := make([]byte, 0, 128)
	msg = append(msg, 0, 0, 0, 0)
	msg = appendU16(msg, unix.RTM_DELROUTE)
	msg = appendU16(msg, unix.NLM_F_REQUEST|unix.NLM_F_ACK)
	msg = appendU32(msg, 1)
	msg = appendU32(msg, 0)
	msg = append(msg, unix.AF_INET)
	msg = append(msg, byte(ones))
	msg = append(msg, 0)
	msg = append(msg, 0)
	msg = append(msg, unix.RT_TABLE_MAIN)
	msg = append(msg, unix.RTPROT_STATIC)
	msg = append(msg, unix.RT_SCOPE_LINK)
	msg = append(msg, unix.RTN_UNICAST)
	msg = appendU32(msg, 0)
	msg = appendRTA(msg, unix.RTA_DST, dst[:4])
	oif := make([]byte, 4)
	binary.LittleEndian.PutUint32(oif, uint32(ifIndex))
	msg = appendRTA(msg, unix.RTA_OIF, oif)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))

	_ = unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// Netlink attribute helpers.

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v), byte(v>>8))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendRTA(b []byte, typ uint16, data []byte) []byte {
	rlen := 4 + len(data)
	b = appendU16(b, uint16(rlen))
	b = appendU16(b, typ)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

// configureExitForwarding enables IP forwarding and NAT masquerade for exit node traffic.
func configureExitForwarding(meshCIDR string) {
	// Enable IP forwarding via procfs (already direct, no exec needed).
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		Warnf("tun: exit: enable ip_forward: %v (try running with sudo)", err)
	} else {
		Infof("tun: exit: ip_forward enabled")
	}

	// Detect the default external interface via netlink.
	extIface := defaultInterface()
	if extIface == "" {
		Warnf("tun: exit: could not detect default interface — masquerade not configured")
		return
	}

	// Add nftables masquerade rule via netlink (replaces iptables exec).
	if err := nftMasquerade(meshCIDR, extIface); err != nil {
		Warnf("tun: exit: nftables masquerade: %v (try running with sudo)", err)
	} else {
		Infof("tun: exit: masquerade enabled: %s → %s", meshCIDR, extIface)
	}
}

// defaultInterface returns the name of the interface used for the default route
// by querying the kernel routing table via netlink (RTM_GETROUTE).
func defaultInterface() string {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return ""
	}
	defer unix.Close(fd)
	_ = unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})

	// Build RTM_GETROUTE for destination 0.0.0.0 (default route).
	msg := make([]byte, 0, 64)
	msg = append(msg, 0, 0, 0, 0) // nlmsghdr: len (fill later)
	msg = appendU16(msg, unix.RTM_GETROUTE)
	msg = appendU16(msg, unix.NLM_F_REQUEST)
	msg = appendU32(msg, 1) // seq
	msg = appendU32(msg, 0) // pid
	// rtmsg
	msg = append(msg, unix.AF_INET) // family
	msg = append(msg, 0)            // dst_len (0 = default)
	msg = append(msg, 0)            // src_len
	msg = append(msg, 0)            // tos
	msg = append(msg, unix.RT_TABLE_MAIN)
	msg = append(msg, unix.RTPROT_UNSPEC)
	msg = append(msg, unix.RT_SCOPE_UNIVERSE)
	msg = append(msg, unix.RTN_UNSPEC)
	msg = appendU32(msg, 0) // flags
	// RTA_DST = 0.0.0.0
	msg = appendRTA(msg, unix.RTA_DST, net.IPv4zero.To4())
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))

	if err := unix.Sendto(fd, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return ""
	}

	buf := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, buf, 0)
	if err != nil || n < 32 {
		return ""
	}

	// Parse the response to find RTA_OIF.
	return parseDefaultRouteOIF(buf[:n])
}

// parseDefaultRouteOIF extracts the output interface name from a netlink RTM_GETROUTE response.
func parseDefaultRouteOIF(buf []byte) string {
	// Skip nlmsghdr (16 bytes) + rtmsg (12 bytes) to reach attributes.
	if len(buf) < 28 {
		return ""
	}
	pos := 28 // start of route attributes
	for pos+4 <= len(buf) {
		rlen := int(binary.LittleEndian.Uint16(buf[pos:]))
		rtype := binary.LittleEndian.Uint16(buf[pos+2:])
		if rlen < 4 || pos+rlen > len(buf) {
			break
		}
		if rtype == unix.RTA_OIF && rlen >= 8 {
			ifIndex := int(binary.LittleEndian.Uint32(buf[pos+4:]))
			iface, err := net.InterfaceByIndex(ifIndex)
			if err != nil {
				return ""
			}
			return iface.Name
		}
		pos += (rlen + 3) &^ 3 // align to 4 bytes
	}
	return ""
}

// nftMasquerade installs an nftables masquerade rule via raw netlink.
// Creates table "pulse_nat" with a POSTROUTING chain and a rule that
// masquerades traffic from meshCIDR going out via extIface.
func nftMasquerade(meshCIDR, extIface string) error {
	_, ipNet, err := net.ParseCIDR(meshCIDR)
	if err != nil {
		return fmt.Errorf("parse CIDR: %w", err)
	}
	srcIP := ipNet.IP.To4()
	if srcIP == nil {
		return fmt.Errorf("IPv4 only")
	}
	ones, _ := ipNet.Mask.Size()

	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	const (
		nfnlSubsysNFTables = 0x0a
		nftMsgNewTable     = 0x00
		nftMsgNewChain     = 0x02
		nftMsgNewRule      = 0x06

		nftaTableName   = 1
		nftaChainName   = 3
		nftaChainTable  = 1
		nftaChainHook   = 4
		nftaChainType   = 7
		nftaChainPolicy = 11

		nftaHookNum      = 1
		nftaHookPriority = 2

		nftaRuleTable       = 1
		nftaRuleChain       = 2
		nftaRuleExpressions = 4

		nftaExprName = 1
		nftaExprData = 2

		// nft_payload registers
		nftaPayloadDregNum = 1
		nftaPayloadBase    = 2
		nftaPayloadOffset  = 3
		nftaPayloadLen     = 4

		// nft_cmp
		nftaCmpSreg = 1
		nftaCmpOp   = 2
		nftaCmpData = 3

		// nft_meta
		nftaMetaDreg = 1
		nftaMetaKey  = 2

		// nft_bitwise
		nftaBitwiseSreg = 1
		nftaBitwiseDreg = 2
		nftaBitwiseLen  = 3
		nftaBitwiseMask = 4
		nftaBitwiseXor  = 5

		// nft_data
		nftaDataValue = 1

		nftReg1 = 1

		nftPayloadNetworkHeader = 1 // NFT_PAYLOAD_NETWORK_HEADER

		nftCmpEq = 0

		nftMetaOifname = 3 // NFT_META_OIFNAME

		nfnlMsgBatchBegin = 0x10
		nfnlMsgBatchEnd   = 0x11

		hookPostrouting = 4
		hookPriNATSrc   = 100
	)

	tableName := "pulse_nat"
	chainName := "postrouting"
	seq := uint32(0)

	nextSeq := func() uint32 {
		seq++
		return seq
	}

	buildMsg := func(msgType uint16, flags uint16, payload []byte) []byte {
		s := nextSeq()
		hdr := make([]byte, 0, 20+len(payload))
		hdr = append(hdr, 0, 0, 0, 0)
		hdr = appendU16(hdr, (nfnlSubsysNFTables<<8)|msgType)
		hdr = appendU16(hdr, unix.NLM_F_REQUEST|flags)
		hdr = appendU32(hdr, s)
		hdr = appendU32(hdr, 0)
		hdr = append(hdr, unix.AF_INET, 0)
		hdr = appendU16(hdr, 0)
		hdr = append(hdr, payload...)
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(hdr)))
		return hdr
	}

	nla := func(typ uint16, data []byte) []byte {
		l := 4 + len(data)
		b := make([]byte, 0, (l+3)&^3)
		b = appendU16(b, uint16(l))
		b = appendU16(b, typ)
		b = append(b, data...)
		for len(b)%4 != 0 {
			b = append(b, 0)
		}
		return b
	}

	nlaStr := func(typ uint16, s string) []byte {
		return nla(typ, append([]byte(s), 0))
	}

	nlaU32 := func(typ uint16, v uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return nla(typ, b)
	}

	nlaNested := func(typ uint16, children ...[]byte) []byte {
		var inner []byte
		for _, c := range children {
			inner = append(inner, c...)
		}
		return nla(typ|0x8000, inner)
	}

	nlaData := func(typ uint16, v []byte) []byte {
		return nlaNested(typ, nla(nftaDataValue, v))
	}

	batchBegin := func() []byte {
		s := nextSeq()
		hdr := make([]byte, 0, 20)
		hdr = append(hdr, 0, 0, 0, 0)
		hdr = appendU16(hdr, nfnlMsgBatchBegin)
		hdr = appendU16(hdr, unix.NLM_F_REQUEST)
		hdr = appendU32(hdr, s)
		hdr = appendU32(hdr, 0)
		hdr = append(hdr, unix.AF_UNSPEC, 0)
		hdr = appendU16(hdr, 0x000a)
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(hdr)))
		return hdr
	}

	batchEnd := func() []byte {
		s := nextSeq()
		hdr := make([]byte, 0, 20)
		hdr = append(hdr, 0, 0, 0, 0)
		hdr = appendU16(hdr, nfnlMsgBatchEnd)
		hdr = appendU16(hdr, unix.NLM_F_REQUEST)
		hdr = appendU32(hdr, s)
		hdr = appendU32(hdr, 0)
		hdr = append(hdr, unix.AF_UNSPEC, 0)
		hdr = appendU16(hdr, 0x000a)
		binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(hdr)))
		return hdr
	}

	tablePayload := nlaStr(nftaTableName, tableName)
	tableMsg := buildMsg(nftMsgNewTable, unix.NLM_F_CREATE|unix.NLM_F_ACK, tablePayload)

	hookAttr := nlaNested(nftaChainHook,
		nlaU32(nftaHookNum, hookPostrouting),
		nlaU32(nftaHookPriority, hookPriNATSrc),
	)
	chainPayload := append([]byte{}, nlaStr(nftaChainTable, tableName)...)
	chainPayload = append(chainPayload, nlaStr(nftaChainName, chainName)...)
	chainPayload = append(chainPayload, hookAttr...)
	chainPayload = append(chainPayload, nlaStr(nftaChainType, "nat")...)
	chainPayload = append(chainPayload, nlaU32(nftaChainPolicy, 1)...)
	chainMsg := buildMsg(nftMsgNewChain, unix.NLM_F_CREATE|unix.NLM_F_ACK, chainPayload)

	buildExpr := func(name string, attrs []byte) []byte {
		return nlaNested(0,
			nlaStr(nftaExprName, name),
			nla(nftaExprData|0x8000, attrs),
		)
	}

	payloadAttrs := append([]byte{},
		nlaU32(nftaPayloadDregNum, nftReg1)...)
	payloadAttrs = append(payloadAttrs, nlaU32(nftaPayloadBase, nftPayloadNetworkHeader)...)
	payloadAttrs = append(payloadAttrs, nlaU32(nftaPayloadOffset, 12)...)
	payloadAttrs = append(payloadAttrs, nlaU32(nftaPayloadLen, 4)...)
	expr1 := buildExpr("payload", payloadAttrs)

	mask := net.CIDRMask(ones, 32)
	bitwiseAttrs := append([]byte{},
		nlaU32(nftaBitwiseSreg, nftReg1)...)
	bitwiseAttrs = append(bitwiseAttrs, nlaU32(nftaBitwiseDreg, nftReg1)...)
	bitwiseAttrs = append(bitwiseAttrs, nlaU32(nftaBitwiseLen, 4)...)
	bitwiseAttrs = append(bitwiseAttrs, nlaData(nftaBitwiseMask, mask)...)
	bitwiseAttrs = append(bitwiseAttrs, nlaData(nftaBitwiseXor, []byte{0, 0, 0, 0})...)
	expr2 := buildExpr("bitwise", bitwiseAttrs)

	cmpAttrs := append([]byte{},
		nlaU32(nftaCmpSreg, nftReg1)...)
	cmpAttrs = append(cmpAttrs, nlaU32(nftaCmpOp, nftCmpEq)...)
	cmpAttrs = append(cmpAttrs, nlaData(nftaCmpData, srcIP.Mask(mask))...)
	expr3 := buildExpr("cmp", cmpAttrs)

	metaAttrs := append([]byte{},
		nlaU32(nftaMetaDreg, nftReg1)...)
	metaAttrs = append(metaAttrs, nlaU32(nftaMetaKey, nftMetaOifname)...)
	expr4 := buildExpr("meta", metaAttrs)

	ifBuf := make([]byte, 16)
	copy(ifBuf, extIface)
	cmpIfAttrs := append([]byte{},
		nlaU32(nftaCmpSreg, nftReg1)...)
	cmpIfAttrs = append(cmpIfAttrs, nlaU32(nftaCmpOp, nftCmpEq)...)
	cmpIfAttrs = append(cmpIfAttrs, nlaData(nftaCmpData, ifBuf[:len(extIface)+1])...)
	expr5 := buildExpr("cmp", cmpIfAttrs)

	expr6 := buildExpr("masq", nil)

	exprs := nlaNested(nftaRuleExpressions, expr1, expr2, expr3, expr4, expr5, expr6)
	rulePayload := append([]byte{}, nlaStr(nftaRuleTable, tableName)...)
	rulePayload = append(rulePayload, nlaStr(nftaRuleChain, chainName)...)
	rulePayload = append(rulePayload, exprs...)
	ruleMsg := buildMsg(nftMsgNewRule, unix.NLM_F_CREATE|unix.NLM_F_APPEND|unix.NLM_F_ACK, rulePayload)

	var batch []byte
	batch = append(batch, batchBegin()...)
	batch = append(batch, tableMsg...)
	batch = append(batch, chainMsg...)
	batch = append(batch, ruleMsg...)
	batch = append(batch, batchEnd()...)

	if err := unix.Sendto(fd, batch, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return fmt.Errorf("sendto: %w", err)
	}

	ackBuf := make([]byte, 4096)
	for {
		n, _, err := unix.Recvfrom(fd, ackBuf, unix.MSG_DONTWAIT)
		if err != nil {
			break
		}
		for off := 0; off+16 <= n; {
			mlen := int(binary.LittleEndian.Uint32(ackBuf[off:]))
			mtype := binary.LittleEndian.Uint16(ackBuf[off+4:])
			if mlen < 16 || off+mlen > n {
				break
			}
			if mtype == unix.NLMSG_ERROR && off+20 <= n {
				errno := int32(binary.LittleEndian.Uint32(ackBuf[off+16:]))
				if errno < 0 && errno != -int32(unix.EEXIST) {
					return fmt.Errorf("nftables error: %v", unix.Errno(-errno))
				}
			}
			off += (mlen + 3) &^ 3
		}
	}

	return nil
}
