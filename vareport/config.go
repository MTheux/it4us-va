package vareport

import (
	"fmt"
	"os"
	"strings"
)

// ConfigFromEnv builds the SysReptor Config from the IT4US_SYSREPTOR_* env
// variables. It fails closed: any missing variable is an error, never a silent
// empty value that would hit SysReptor unauthenticated or against no design.
func ConfigFromEnv() (Config, error) {
	cfg := Config{
		BaseURL:  strings.TrimSpace(os.Getenv("IT4US_SYSREPTOR_URL")),
		Token:    strings.TrimSpace(os.Getenv("IT4US_SYSREPTOR_TOKEN")),
		DesignID: strings.TrimSpace(os.Getenv("IT4US_SYSREPTOR_DESIGN_ID")),
	}
	var missing []string
	if cfg.BaseURL == "" {
		missing = append(missing, "IT4US_SYSREPTOR_URL")
	}
	if cfg.Token == "" {
		missing = append(missing, "IT4US_SYSREPTOR_TOKEN")
	}
	if cfg.DesignID == "" {
		missing = append(missing, "IT4US_SYSREPTOR_DESIGN_ID")
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("configuração SysReptor incompleta: defina %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}
