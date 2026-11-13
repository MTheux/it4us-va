package vascan

import (
	"strings"
	"testing"
)

func TestParseGMPCVEInfoMatchesExactIDAndKeepsFeedMetadata(t *testing.T) {
	inner := `<info id="CVE-2024-1111"><name>CVE-2024-1111</name><cve><description>Unrelated</description></cve></info>` +
		`<info id="CVE-2024-2222"><name>CVE-2024-2222</name><creation_time>2024-01-01T00:00:00Z</creation_time><update_time>2026-11-13T02:15:00Z</update_time>` +
		`<cve><severity>7.5</severity><cvss_vector>CVSS:3.1/AV:N</cvss_vector><description>Local record</description><products>cpe:/a:example</products></cve></info><info_count>424948</info_count>`
	got, err := parseGMPCVEInfo(inner, "CVE-2024-2222")
	if err != nil || got.Description != "Local record" || got.FeedCount != 424948 || got.Updated != "2026-11-13T02:15:00Z" || got.Vector != "CVSS:3.1/AV:N" {
		t.Fatalf("unexpected local CVE record: %+v, %v", got, err)
	}
	_, err = parseGMPCVEInfo(inner, "CVE-2024-3333")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected exact-ID miss, got %v", err)
	}
}
