package vareport

import "testing"

func TestConfigFromEnvMissingFailsClosed(t *testing.T) {
	t.Setenv("IT4US_SYSREPTOR_URL", "http://x")
	t.Setenv("IT4US_SYSREPTOR_TOKEN", "")
	t.Setenv("IT4US_SYSREPTOR_DESIGN_ID", "d1")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("esperava erro com token ausente")
	}
}

func TestConfigFromEnvOK(t *testing.T) {
	t.Setenv("IT4US_SYSREPTOR_URL", "http://x")
	t.Setenv("IT4US_SYSREPTOR_TOKEN", "tok")
	t.Setenv("IT4US_SYSREPTOR_DESIGN_ID", "d1")
	c, err := ConfigFromEnv()
	if err != nil || c.DesignID != "d1" || c.Token != "tok" {
		t.Fatalf("c=%+v err=%v", c, err)
	}
}
