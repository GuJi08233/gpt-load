package keypool

import (
	"encoding/hex"
	"errors"
	"fmt"
	"gpt-load/internal/models"
	"gpt-load/internal/store"
	"hash/fnv"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

// SelectKeyWithSession returns a key for the given group, optionally pinned to the session.
//
// Behavior:
//   - sessionKey == "" or ttlSec <= 0: equivalent to SelectKey, returns isSticky=false.
//   - Mapping hit and the mapped key is still active: returns that key with isSticky=true.
//     The round-robin position is NOT advanced (Rotate is skipped).
//   - Mapping hit but key is invalid/missing: clears the stale mapping, falls through to round-robin
//     and writes a fresh mapping for the newly-selected key.
//   - No mapping: round-robin selects a key, writes a fresh mapping with TTL, returns isSticky=false.
func (p *KeyProvider) SelectKeyWithSession(groupID uint, sessionKey string, ttlSec int) (*models.APIKey, bool, error) {
	if sessionKey == "" || ttlSec <= 0 {
		apiKey, err := p.SelectKey(groupID)
		return apiKey, false, err
	}

	stickyKey := stickyStoreKey(groupID, sessionKey)
	ttl := time.Duration(ttlSec) * time.Second

	// 1. Check existing mapping.
	if raw, err := p.store.Get(stickyKey); err == nil && len(raw) > 0 {
		keyID, parseErr := strconv.ParseUint(string(raw), 10, 64)
		if parseErr == nil {
			if apiKey, ok := p.loadActiveKey(uint(keyID), groupID); ok {
				return apiKey, true, nil
			}
		}
		// Stale or unparsable mapping — clear it.
		if delErr := p.store.Delete(stickyKey); delErr != nil {
			logrus.WithError(delErr).WithField("sticky_key", stickyKey).Debug("Failed to delete stale sticky mapping")
		}
	} else if err != nil && !errors.Is(err, store.ErrNotFound) {
		logrus.WithError(err).WithField("sticky_key", stickyKey).Debug("Failed to read sticky mapping, falling through")
	}

	// 2. Fall through: regular round-robin selection.
	apiKey, err := p.SelectKey(groupID)
	if err != nil {
		return nil, false, err
	}

	// 3. Write new mapping.
	value := []byte(strconv.FormatUint(uint64(apiKey.ID), 10))
	if setErr := p.store.Set(stickyKey, value, ttl); setErr != nil {
		logrus.WithError(setErr).WithField("sticky_key", stickyKey).Warn("Failed to write sticky mapping")
	}

	return apiKey, false, nil
}

// ClearSticky removes the session→key mapping. Called by the proxy layer when a sticky-hit key fails,
// so the next request for the same session is re-routed to a fresh key.
func (p *KeyProvider) ClearSticky(groupID uint, sessionKey string) error {
	if sessionKey == "" {
		return nil
	}
	return p.store.Delete(stickyStoreKey(groupID, sessionKey))
}

// loadActiveKey reads the key HASH and returns the decrypted APIKey only when status == active.
// Mirrors the relevant slice of SelectKey to avoid touching Rotate on sticky hits.
func (p *KeyProvider) loadActiveKey(keyID, groupID uint) (*models.APIKey, bool) {
	keyHashKey := fmt.Sprintf("key:%d", keyID)
	keyDetails, err := p.store.HGetAll(keyHashKey)
	if err != nil || len(keyDetails) == 0 {
		return nil, false
	}
	if keyDetails["status"] != models.KeyStatusActive {
		return nil, false
	}

	failureCount, _ := strconv.ParseInt(keyDetails["failure_count"], 10, 64)
	createdAt, _ := strconv.ParseInt(keyDetails["created_at"], 10, 64)

	encryptedKeyValue := keyDetails["key_string"]
	decryptedKeyValue, decErr := p.encryptionSvc.Decrypt(encryptedKeyValue)
	if decErr != nil {
		// Backward-compatible: treat as plaintext if decryption fails.
		decryptedKeyValue = encryptedKeyValue
	}

	return &models.APIKey{
		ID:           keyID,
		KeyValue:     decryptedKeyValue,
		Status:       keyDetails["status"],
		FailureCount: failureCount,
		GroupID:      groupID,
		CreatedAt:    time.Unix(createdAt, 0),
	}, true
}

// stickyStoreKey produces "group:{id}:sticky:{fnv64hex(sessionKey)}" — bounded length, safe characters.
func stickyStoreKey(groupID uint, sessionKey string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(sessionKey))
	return fmt.Sprintf("group:%d:sticky:%s", groupID, hex.EncodeToString(h.Sum(nil)))
}
