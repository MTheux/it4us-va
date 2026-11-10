package agent

import (
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// IT4US VA suporta Claude e OpenCode como providers de IA (além de ollama/openai).

func TestConfigFrom_OpenCode(t *testing.T) {
	c := ConfigFrom("opencode", "", "", "", "")
	if c.Format != llm.FormatOpenAI {
		t.Fatalf("opencode Format = %v, quer FormatOpenAI", c.Format)
	}
	if c.BaseURL != DefaultOpenCodeBaseURL {
		t.Fatalf("opencode BaseURL = %q, quer %q", c.BaseURL, DefaultOpenCodeBaseURL)
	}
	if c.APIKey == "" {
		t.Fatal("opencode nao deve exigir chave de nuvem (sentinel local)")
	}
	if c.Model == "" {
		t.Fatal("opencode deve ter modelo default")
	}
}

func TestConfigFrom_OpenCode_CustomURLAppendsV1(t *testing.T) {
	c := ConfigFrom("opencode", "", "http://host:9000", "", "")
	if c.BaseURL != "http://host:9000/v1" {
		t.Fatalf("BaseURL = %q, quer sufixo /v1", c.BaseURL)
	}
}

func TestConfigFrom_Claude(t *testing.T) {
	c := ConfigFrom("anthropic", "", "", "sk-test", "")
	if c.Format != llm.FormatAnthropic {
		t.Fatalf("claude Format = %v, quer FormatAnthropic", c.Format)
	}
}
