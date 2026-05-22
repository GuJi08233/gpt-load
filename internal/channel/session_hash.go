package channel

import (
	"encoding/hex"
	"encoding/json"
	"hash/fnv"

	"github.com/gin-gonic/gin"
)

// extractSessionKey is the shared core logic for all ChannelProxy.ExtractSessionKey implementations.
//
// strategy:
//   - "header_then_hash": prefer header, fall back to body hash
//   - "header_only":      header only
//   - "hash_only":        body hash only
//
// bodyHashSrc returns the byte slice to hash; nil falls back to the whole body.
// Returns "" when no identifier can be derived (caller falls back to round-robin).
func extractSessionKey(c *gin.Context, body []byte, strategy, headerName string, bodyHashSrc func([]byte) []byte) string {
	if strategy != "hash_only" && headerName != "" {
		if v := c.GetHeader(headerName); v != "" {
			return "h:" + v
		}
	}
	if strategy == "header_only" {
		return ""
	}

	var src []byte
	if bodyHashSrc != nil {
		src = bodyHashSrc(body)
	} else {
		src = body
	}
	if len(src) == 0 {
		return ""
	}
	return "b:" + fnv64Hex(src)
}

// fnv64Hex computes FNV-64a hex of b.
func fnv64Hex(b []byte) string {
	h := fnv.New64a()
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// openaiHashSource builds a stable session fingerprint for OpenAI chat-completions style bodies.
// Uses messages[0] (the first turn never changes across a conversation).
func openaiHashSource(body []byte) []byte {
	type req struct {
		Messages []json.RawMessage `json:"messages"`
	}
	var r req
	if err := json.Unmarshal(body, &r); err != nil || len(r.Messages) == 0 {
		return nil
	}
	return r.Messages[0]
}

// anthropicHashSource builds the fingerprint as system + messages[0].
// Anthropic's prompt cache spans system+messages, so both contribute to a stable session identity.
func anthropicHashSource(body []byte) []byte {
	type req struct {
		System   json.RawMessage   `json:"system"`
		Messages []json.RawMessage `json:"messages"`
	}
	var r req
	if err := json.Unmarshal(body, &r); err != nil || len(r.Messages) == 0 {
		return nil
	}
	out := make([]byte, 0, len(r.System)+len(r.Messages[0])+1)
	out = append(out, r.System...)
	out = append(out, '|')
	out = append(out, r.Messages[0]...)
	return out
}

// geminiHashSource builds the fingerprint from systemInstruction + contents[0] for native format,
// or messages[0] when an OpenAI-compatible body is present (v1beta/openai path).
func geminiHashSource(body []byte) []byte {
	type req struct {
		SystemInstruction  json.RawMessage   `json:"systemInstruction"`
		SystemInstructionS json.RawMessage   `json:"system_instruction"`
		Contents           []json.RawMessage `json:"contents"`
		Messages           []json.RawMessage `json:"messages"`
	}
	var r req
	if err := json.Unmarshal(body, &r); err != nil {
		return nil
	}
	if len(r.Contents) > 0 {
		sys := r.SystemInstruction
		if len(sys) == 0 {
			sys = r.SystemInstructionS
		}
		out := make([]byte, 0, len(sys)+len(r.Contents[0])+1)
		out = append(out, sys...)
		out = append(out, '|')
		out = append(out, r.Contents[0]...)
		return out
	}
	if len(r.Messages) > 0 {
		return r.Messages[0]
	}
	return nil
}

// openaiResponseHashSource handles OpenAI Responses API:
// - messages[0] when present
// - else the input field (string or structured first turn)
func openaiResponseHashSource(body []byte) []byte {
	type req struct {
		Messages []json.RawMessage `json:"messages"`
		Input    json.RawMessage   `json:"input"`
	}
	var r req
	if err := json.Unmarshal(body, &r); err != nil {
		return nil
	}
	if len(r.Messages) > 0 {
		return r.Messages[0]
	}
	if len(r.Input) > 0 {
		return r.Input
	}
	return nil
}
