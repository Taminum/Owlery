// Package keyrotate re-encrypts stored panel tokens and two-factor secrets under the active master key.
package keyrotate

import (
	"context"
	"fmt"

	"github.com/Taminum/Owlery/internal/secrets"
	"github.com/Taminum/Owlery/internal/store"
)

type Result struct {
	Rotated int
	Current int // already on the active key
	Raced   int // changed by someone else mid-run; left alone, run again
}

// Run re-seals every credential that is not on the active key version. Each
// replacement is compare-and-set on the old key version and verified by decrypting
// the new ciphertext before it is stored, so a failure never leaves a panel unreadable.
func Run(ctx context.Context, st *store.Store, ring *secrets.Keyring) (Result, error) {
	var res Result
	refs, err := st.AllCredentials(ctx)
	if err != nil {
		return res, err
	}
	for _, ref := range refs {
		next, changed, err := ring.Reseal(ref.PanelID, ref.Sealed)
		if err != nil {
			return res, fmt.Errorf("panel %s: cannot decrypt with the available keys (is its old key still in the keyring?)", ref.PanelID)
		}
		if !changed {
			res.Current++
			continue
		}
		if _, err := ring.Open(ref.PanelID, next); err != nil {
			return res, fmt.Errorf("panel %s: re-encrypted value failed verification", ref.PanelID)
		}
		ok, err := st.ReplaceCredentialIf(ctx, ref.PanelID, ref.Sealed.KeyVersion, next)
		if err != nil {
			return res, err
		}
		if ok {
			res.Rotated++
		} else {
			res.Raced++
		}
	}
	totps, err := st.AllTOTP(ctx)
	if err != nil {
		return res, err
	}
	for _, ref := range totps {
		aad := store.TOTPAAD(ref.AccountID)
		next, changed, err := ring.Reseal(aad, ref.Sealed)
		if err != nil {
			return res, fmt.Errorf("account %s: cannot decrypt the two-factor secret with the available keys", ref.AccountID)
		}
		if !changed {
			res.Current++
			continue
		}
		if _, err := ring.Open(aad, next); err != nil {
			return res, fmt.Errorf("account %s: re-encrypted value failed verification", ref.AccountID)
		}
		ok, err := st.ReplaceTOTPIf(ctx, ref.AccountID, ref.Sealed.KeyVersion, next)
		if err != nil {
			return res, err
		}
		if ok {
			res.Rotated++
		} else {
			res.Raced++
		}
	}
	return res, nil
}
