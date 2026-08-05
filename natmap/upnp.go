// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

// Package natmap provides optional NAT helpers (Phase 2b: UPnP IGD port mapping).
// TURN and other relays are out of scope until Phase 3+.
//
// IPv6 note: UPnP IGD is an IPv4 NAT mechanism. Nodes with a globally routable IPv6
// address are directly reachable without any port mapping and do not use this package.
// UPnP mapping is only attempted when the node's public address is obtained via STUN
// or natsense and the socket is behind an IPv4 NAT.
package natmap

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
)

// Description is written into PortMappingDescription so we can verify ownership
// before DeletePortMapping (IGD delete is keyed only by ext-port + protocol).
const Description = "a2al-quic"

// LeaseSeconds is the IGD lease duration requested on AddPortMapping.
const LeaseSeconds = 3600

// maxPortTry is the number of consecutive external ports tried when the preferred
// port is already mapped to a different internal host (same-LAN conflict).
const maxPortTry = 10

// Mapping is one successfully registered UDP port forward on the LAN IGD.
type Mapping struct {
	ExternalIP     string
	ExternalPort   int
	InternalPort   int
	InternalClient string
	Lease          time.Duration
	cleanup        func()
}

// Cleanup deletes this mapping only after verifying it is still ours.
// Safe to call multiple times.
func (m *Mapping) Cleanup() {
	if m == nil || m.cleanup == nil {
		return
	}
	m.cleanup()
	m.cleanup = nil
}

// Ours reports whether a GetSpecificPortMappingEntry result is owned by this
// process's registration (same client, internal port, and a2al description).
// Empty description → not ours (strict: never delete unverified entries).
func Ours(wantInternalPort int, wantClient string, gotInternalPort uint16, gotClient string, enabled bool, desc string) bool {
	if !enabled || wantClient == "" || gotClient != wantClient {
		return false
	}
	if int(gotInternalPort) != wantInternalPort {
		return false
	}
	return desc == Description
}

// entryBlocksUs reports whether an existing IGD port-mapping entry prevents us
// from using extPort for internalClient:internalPort. hasEntry is false when
// GetSpecificPortMappingEntry returned an error (port appears unmapped).
func entryBlocksUs(hasEntry bool, gotInternalPort uint16, existingClient string, enabled bool, desc string, internalPort int, internalClient string) bool {
	if !hasEntry {
		return false
	}
	if existingClient != "" && existingClient != internalClient {
		return true
	}
	if enabled && int(gotInternalPort) != internalPort {
		return true
	}
	if enabled && desc != "" && desc != Description {
		return true
	}
	return false
}

// MapUDPPort asks the LAN IGD to forward UDP externalPort -> internalClient:internalPort
// using the same port number on the WAN side when possible (predictable QUIC URLs).
// Cleanup verifies ownership before DeletePortMapping.
func MapUDPPort(ctx context.Context, internalPort int, internalClient string) (*Mapping, error) {
	if internalPort <= 0 || internalPort > 65535 {
		return nil, fmt.Errorf("natmap: invalid internal port %d", internalPort)
	}
	if internalClient == "" {
		return nil, fmt.Errorf("natmap: empty internal client IP")
	}

	dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	clients, _, derr := internetgateway1.NewWANIPConnection1ClientsCtx(dctx)
	if derr == nil {
		for _, c := range clients {
			if m, e := mapWANIP1(dctx, c, internalPort, internalClient); e == nil {
				return m, nil
			}
		}
	}

	pclients, _, perr := internetgateway1.NewWANPPPConnection1ClientsCtx(dctx)
	if perr == nil {
		for _, c := range pclients {
			if m, e := mapWANPPP1(dctx, c, internalPort, internalClient); e == nil {
				return m, nil
			}
		}
	}

	if derr != nil {
		return nil, derr
	}
	if perr != nil {
		return nil, perr
	}
	return nil, fmt.Errorf("natmap: no UPnP gateway responded")
}

// RenewUDPPort refreshes an existing mapping on extPort (same internal binding)
// and returns the current IGD external IP plus lease duration.
func RenewUDPPort(ctx context.Context, extPort, internalPort int, internalClient string) (externalIP string, lease time.Duration, err error) {
	if extPort <= 0 || extPort > 65535 || internalPort <= 0 || internalPort > 65535 {
		return "", 0, fmt.Errorf("natmap: invalid port")
	}
	if internalClient == "" {
		return "", 0, fmt.Errorf("natmap: empty internal client IP")
	}

	dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	clients, _, derr := internetgateway1.NewWANIPConnection1ClientsCtx(dctx)
	if derr == nil {
		for _, c := range clients {
			if ip, e := renewWANIP1(dctx, c, uint16(extPort), internalPort, internalClient); e == nil {
				return ip, time.Duration(LeaseSeconds) * time.Second, nil
			}
		}
	}

	pclients, _, perr := internetgateway1.NewWANPPPConnection1ClientsCtx(dctx)
	if perr == nil {
		for _, c := range pclients {
			if ip, e := renewWANPPP1(dctx, c, uint16(extPort), internalPort, internalClient); e == nil {
				return ip, time.Duration(LeaseSeconds) * time.Second, nil
			}
		}
	}

	if derr != nil {
		return "", 0, derr
	}
	if perr != nil {
		return "", 0, perr
	}
	return "", 0, fmt.Errorf("natmap: renew: no UPnP gateway responded")
}

func mapWANIP1(ctx context.Context, client *internetgateway1.WANIPConnection1, internalPort int, internalClient string) (*Mapping, error) {
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(extIP) == nil {
		return nil, fmt.Errorf("natmap: bad external IP %q", extIP)
	}

	for try := 0; try < maxPortTry; try++ {
		extPort := uint16(internalPort + try)
		gotPort, existingClient, enabled, desc, _, qerr := client.GetSpecificPortMappingEntryCtx(ctx, "", extPort, "UDP")
		if entryBlocksUs(qerr == nil, gotPort, existingClient, enabled, desc, internalPort, internalClient) {
			continue
		}

		if merr := client.AddPortMappingCtx(ctx, "", extPort, "UDP",
			uint16(internalPort), internalClient, true, Description, LeaseSeconds); merr != nil {
			continue
		}

		ep := extPort
		iport := internalPort
		iclient := internalClient
		return &Mapping{
			ExternalIP:     extIP,
			ExternalPort:   int(ep),
			InternalPort:   iport,
			InternalClient: iclient,
			Lease:          time.Duration(LeaseSeconds) * time.Second,
			cleanup: func() {
				cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				safeDeleteWANIP1(cctx, client, ep, iport, iclient)
			},
		}, nil
	}
	return nil, fmt.Errorf("natmap: no free external port in [%d, %d)", internalPort, internalPort+maxPortTry)
}

func mapWANPPP1(ctx context.Context, client *internetgateway1.WANPPPConnection1, internalPort int, internalClient string) (*Mapping, error) {
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return nil, err
	}
	if net.ParseIP(extIP) == nil {
		return nil, fmt.Errorf("natmap: bad external IP %q", extIP)
	}

	for try := 0; try < maxPortTry; try++ {
		extPort := uint16(internalPort + try)
		gotPort, existingClient, enabled, desc, _, qerr := client.GetSpecificPortMappingEntryCtx(ctx, "", extPort, "UDP")
		if entryBlocksUs(qerr == nil, gotPort, existingClient, enabled, desc, internalPort, internalClient) {
			continue
		}

		if merr := client.AddPortMappingCtx(ctx, "", extPort, "UDP",
			uint16(internalPort), internalClient, true, Description, LeaseSeconds); merr != nil {
			continue
		}

		ep := extPort
		iport := internalPort
		iclient := internalClient
		return &Mapping{
			ExternalIP:     extIP,
			ExternalPort:   int(ep),
			InternalPort:   iport,
			InternalClient: iclient,
			Lease:          time.Duration(LeaseSeconds) * time.Second,
			cleanup: func() {
				cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				safeDeleteWANPPP1(cctx, client, ep, iport, iclient)
			},
		}, nil
	}
	return nil, fmt.Errorf("natmap: no free external port in [%d, %d)", internalPort, internalPort+maxPortTry)
}

func renewWANIP1(ctx context.Context, client *internetgateway1.WANIPConnection1, extPort uint16, internalPort int, internalClient string) (string, error) {
	gotPort, existingClient, enabled, desc, _, qerr := client.GetSpecificPortMappingEntryCtx(ctx, "", extPort, "UDP")
	if entryBlocksUs(qerr == nil, gotPort, existingClient, enabled, desc, internalPort, internalClient) {
		if qerr == nil && existingClient != "" && existingClient != internalClient {
			return "", fmt.Errorf("natmap: renew: port owned by %s", existingClient)
		}
		return "", fmt.Errorf("natmap: renew: port %d conflict", extPort)
	}

	if err := client.AddPortMappingCtx(ctx, "", extPort, "UDP",
		uint16(internalPort), internalClient, true, Description, LeaseSeconds); err != nil {
		return "", err
	}
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return "", err
	}
	if net.ParseIP(extIP) == nil {
		return "", fmt.Errorf("natmap: bad external IP %q", extIP)
	}
	return extIP, nil
}

func renewWANPPP1(ctx context.Context, client *internetgateway1.WANPPPConnection1, extPort uint16, internalPort int, internalClient string) (string, error) {
	gotPort, existingClient, enabled, desc, _, qerr := client.GetSpecificPortMappingEntryCtx(ctx, "", extPort, "UDP")
	if entryBlocksUs(qerr == nil, gotPort, existingClient, enabled, desc, internalPort, internalClient) {
		if qerr == nil && existingClient != "" && existingClient != internalClient {
			return "", fmt.Errorf("natmap: renew: port owned by %s", existingClient)
		}
		return "", fmt.Errorf("natmap: renew: port %d conflict", extPort)
	}

	if err := client.AddPortMappingCtx(ctx, "", extPort, "UDP",
		uint16(internalPort), internalClient, true, Description, LeaseSeconds); err != nil {
		return "", err
	}
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return "", err
	}
	if net.ParseIP(extIP) == nil {
		return "", fmt.Errorf("natmap: bad external IP %q", extIP)
	}
	return extIP, nil
}

func safeDeleteWANIP1(ctx context.Context, client *internetgateway1.WANIPConnection1, extPort uint16, internalPort int, internalClient string) {
	gotPort, gotClient, enabled, desc, _, err := client.GetSpecificPortMappingEntryCtx(ctx, "", extPort, "UDP")
	if err != nil {
		slog.Debug("upnp: skip delete, query failed", "ext_port", extPort, "err", err)
		return
	}
	if !Ours(internalPort, internalClient, gotPort, gotClient, enabled, desc) {
		slog.Debug("upnp: skip delete, not ours", "ext_port", extPort,
			"client", gotClient, "enabled", enabled, "desc", desc)
		return
	}
	_ = client.DeletePortMappingCtx(ctx, "", extPort, "UDP")
}

func safeDeleteWANPPP1(ctx context.Context, client *internetgateway1.WANPPPConnection1, extPort uint16, internalPort int, internalClient string) {
	gotPort, gotClient, enabled, desc, _, err := client.GetSpecificPortMappingEntryCtx(ctx, "", extPort, "UDP")
	if err != nil {
		slog.Debug("upnp: skip delete, query failed", "ext_port", extPort, "err", err)
		return
	}
	if !Ours(internalPort, internalClient, gotPort, gotClient, enabled, desc) {
		slog.Debug("upnp: skip delete, not ours", "ext_port", extPort,
			"client", gotClient, "enabled", enabled, "desc", desc)
		return
	}
	_ = client.DeletePortMappingCtx(ctx, "", extPort, "UDP")
}

// LocalIPv4ForUPnP returns an IPv4 address suitable as IGD "internal client"
// (typically the LAN address used for outbound UDP).
func LocalIPv4ForUPnP() string {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return ""
	}
	defer conn.Close()
	ip := conn.LocalAddr().(*net.UDPAddr).IP
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ""
}

// QUICURL builds a quic:// URL for an endpoint string (host + port).
func QUICURL(host string, port int) string {
	return "quic://" + net.JoinHostPort(host, strconv.Itoa(port))
}
