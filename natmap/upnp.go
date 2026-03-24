// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package natmap provides optional NAT helpers (Phase 2b: UPnP IGD port mapping).
// TURN and other relays are out of scope until Phase 3+.
package natmap

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
)

const upnpDescription = "a2al-quic"

// MapUDPPort asks the LAN IGD to forward UDP externalPort -> internalClient:internalPort
// using the same port number on the WAN side (required for predictable QUIC URLs).
// Returns cleanup (DeletePortMapping). Errors if no gateway or mapping is rejected.
func MapUDPPort(ctx context.Context, internalPort int, internalClient string) (externalIP string, externalPort int, cleanup func(), err error) {
	if internalPort <= 0 || internalPort > 65535 {
		return "", 0, nil, fmt.Errorf("natmap: invalid internal port %d", internalPort)
	}
	if internalClient == "" {
		return "", 0, nil, fmt.Errorf("natmap: empty internal client IP")
	}

	dctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	clients, _, derr := internetgateway1.NewWANIPConnection1ClientsCtx(dctx)
	if derr == nil {
		for _, c := range clients {
			if extIP, extPort, del, e := mapWANIP1(dctx, c, internalPort, internalClient); e == nil {
				return extIP, extPort, del, nil
			}
		}
	}

	pclients, _, perr := internetgateway1.NewWANPPPConnection1ClientsCtx(dctx)
	if perr == nil {
		for _, c := range pclients {
			if extIP, extPort, del, e := mapWANPPP1(dctx, c, internalPort, internalClient); e == nil {
				return extIP, extPort, del, nil
			}
		}
	}

	if derr != nil {
		return "", 0, nil, derr
	}
	if perr != nil {
		return "", 0, nil, perr
	}
	return "", 0, nil, fmt.Errorf("natmap: no UPnP gateway responded")
}

func mapWANIP1(ctx context.Context, client *internetgateway1.WANIPConnection1, internalPort int, internalClient string) (string, int, func(), error) {
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return "", 0, nil, err
	}
	if net.ParseIP(extIP) == nil {
		return "", 0, nil, fmt.Errorf("natmap: bad external IP %q", extIP)
	}

	extPort := uint16(internalPort)
	err = client.AddPortMappingCtx(ctx,
		"",
		extPort,
		"UDP",
		uint16(internalPort),
		internalClient,
		true,
		upnpDescription,
		3600,
	)
	if err != nil {
		return "", 0, nil, err
	}

	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = client.DeletePortMappingCtx(cctx, "", extPort, "UDP")
	}
	return extIP, int(extPort), cleanup, nil
}

func mapWANPPP1(ctx context.Context, client *internetgateway1.WANPPPConnection1, internalPort int, internalClient string) (string, int, func(), error) {
	extIP, err := client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		return "", 0, nil, err
	}
	if net.ParseIP(extIP) == nil {
		return "", 0, nil, fmt.Errorf("natmap: bad external IP %q", extIP)
	}

	extPort := uint16(internalPort)
	err = client.AddPortMappingCtx(ctx,
		"",
		extPort,
		"UDP",
		uint16(internalPort),
		internalClient,
		true,
		upnpDescription,
		3600,
	)
	if err != nil {
		return "", 0, nil, err
	}

	cleanup := func() {
		cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = client.DeletePortMappingCtx(cctx, "", extPort, "UDP")
	}
	return extIP, int(extPort), cleanup, nil
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
