// Copyright 2026 The A2AL Authors. All rights reserved.
// SPDX-License-Identifier: MPL-2.0

package group

import (
	"github.com/a2al/a2al"
	"github.com/fxamacker/cbor/v2"
)

// budgetBody is the CBOR body of a kind=budget entry.
// The creator or admin allocates an amount to a target AID.
type budgetBody struct {
	TargetAID []byte `cbor:"1,keyasint"`
	Amount    int64  `cbor:"2,keyasint"` // positive; unit is application-defined
	ModelTag  string `cbor:"3,keyasint,omitempty"`
}

// spendBody is the CBOR body of a kind=spend entry.
// An agent self-reports its expenditure.
type spendBody struct {
	Amount   int64  `cbor:"1,keyasint"` // positive
	ModelTag string `cbor:"2,keyasint,omitempty"`
}

// EncodeBudgetBody returns the CBOR body for a budget entry.
func EncodeBudgetBody(target a2al.Address, amount int64, modelTag string) []byte {
	b, _ := cbor.Marshal(budgetBody{
		TargetAID: target[:],
		Amount:    amount,
		ModelTag:  modelTag,
	})
	return b
}

// EncodeSpendBody returns the CBOR body for a spend entry.
func EncodeSpendBody(amount int64, modelTag string) []byte {
	b, _ := cbor.Marshal(spendBody{Amount: amount, ModelTag: modelTag})
	return b
}

// computeBalance returns the remaining balance for aid:
//
//	balance = Σ budget entries targeting aid − Σ spend entries authored by aid
//
// entries must be in causal order. The result is a soft limit; the protocol
// does not enforce it. Enforcement is delegated to the creator/admin.
func computeBalance(entries []Entry, aid a2al.Address) int64 {
	var balance int64
	for _, e := range entries {
		switch e.Kind {
		case KindBudget:
			var b budgetBody
			if err := cbor.Unmarshal(e.Body, &b); err != nil || len(b.TargetAID) != 21 {
				continue
			}
			var target a2al.Address
			copy(target[:], b.TargetAID)
			if target == aid {
				balance += b.Amount
			}
		case KindSpend:
			if e.Author == aid {
				var s spendBody
				if err := cbor.Unmarshal(e.Body, &s); err != nil {
					continue
				}
				balance -= s.Amount
			}
		}
	}
	return balance
}
