package vacheck_test

import (
	"testing"

	"github.com/MTheux/it4us-va/vacheck"
)

func TestNmapInventoryRetainsOrdinaryOpenServiceAndCPE(t *testing.T) {
	raw := []byte(`<nmaprun><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Example Service" version="2.4"><cpe>cpe:/a:example:service:2.4</cpe></service></port></ports></host></nmaprun>`)
	services, err := vacheck.ParseNmapInventory(raw)
	if err != nil || len(services) != 1 {
		t.Fatalf("services=%+v err=%v", services, err)
	}
	if services[0].Port != 8080 || services[0].Version != "2.4" || len(services[0].CPE) != 1 {
		t.Fatalf("service=%+v", services[0])
	}
	candidates, err := vacheck.ParseNmap(raw)
	if err != nil || len(candidates) != 0 {
		t.Fatalf("ordinary service should stay inventory only: %+v %v", candidates, err)
	}
}
