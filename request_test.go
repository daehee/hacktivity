package hacktivity

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_GetLatestReports(t *testing.T) {
	client := NewClient()
	urls, err := client.GetLatestReports(100)
	assert.NoError(t, err)
	assert.Len(t, urls, 100)
}

func TestClient_GetHacktivity(t *testing.T) {
	client := NewClient()
	got, err := client.GetHacktivity("https://hackerone.com/reports/1019891")
	assert.NoError(t, err)

	assert.Equal(t, "Named pipe connection inteception", got.Title)
	assert.Equal(t, []string{"CVE-2020-28912"}, got.CVEs)
	assert.Equal(t, "gabriel_sztejnworcel", got.Researcher)
}
