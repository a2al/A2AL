// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package transport

var (
	_ Transport = (*MemTransport)(nil)
	_ Transport = (*UDPTransport)(nil)
)
