package hacktivity

import (
	"fmt"
	"strings"

	"github.com/daehee/nvd"
)

type Hacktivity struct {
	URL          string
	ReportID     int
	Title        string
	Description  string
	Severity     string
	Researcher   string
	Vendor       string
	VendorHandle string
	CVEs         []string
	SubmittedAt  string
	DisclosedAt  string
}

func (c *Client) jsonToHacktivity(u string, raw []byte) (Hacktivity, error) {
	parser := c.parserPool.Get()
	defer c.parserPool.Put(parser)
	v, err := parser.ParseBytes(raw)
	if err != nil {
		return Hacktivity{}, fmt.Errorf("error parsing report json: %v", err)
	}

	reportID := v.GetInt("id")
	title := string(v.GetStringBytes("title"))
	severity := string(v.GetStringBytes("severity_rating"))
	researcher := string(v.GetStringBytes("reporter", "username"))
	vendor := string(v.GetStringBytes("team", "profile", "name"))
	vendorHandle := string(v.GetStringBytes("team", "handle"))
	submittedAt := string(v.GetStringBytes("submitted_at"))
	disclosedAt := string(v.GetStringBytes("disclosed_at"))

	var description string
	ss := v.GetArray("summaries")
	for _, s := range ss {
		if s.Exists("content") {
			description = string(s.GetStringBytes("content"))
		}
	}

	// start with HackerOne's own CVE ID disclosure
	var cveIDs []string
	tmp := v.GetArray("cve_ids")
	for _, s := range tmp {
		cveIDs = append(cveIDs, string(s.GetStringBytes()))
	}
	cveIDs = extractCVEIDs(cveIDs, string(v.GetStringBytes("vulnerability_information")))

	// extract CVEs from comments thread
	comments := v.GetArray("activities")
	for _, comment := range comments {
		cveIDs = extractCVEIDs(cveIDs, string(comment.GetStringBytes("message")))
	}

	// extract CVEs from summaries
	summaries := v.GetArray("summaries")
	for _, summary := range summaries {
		cveIDs = extractCVEIDs(cveIDs, string(summary.GetStringBytes("content")))
	}

	// extract CVEs from title
	cveIDs = extractCVEIDs(cveIDs, title)

	return Hacktivity{
		ReportID:     reportID,
		URL:          u,
		Title:        title,
		Description:  description,
		Severity:     severity,
		Researcher:   researcher,
		CVEs:         cveIDs,
		Vendor:       vendor,
		VendorHandle: vendorHandle,
		SubmittedAt:  submittedAt,
		DisclosedAt:  disclosedAt,
	}, nil
}

func extractCVEIDs(cveIDs []string, r string) []string {
	res := nvd.CVERx.FindAllString(r, -1)
	seen := make(map[string]bool)
	// mark H1 provided cve IDs as seen
	for _, c := range cveIDs {
		seen[c] = true
	}
	for _, s := range res {
		s = strings.ToUpper(s)
		if ok := seen[s]; ok {
			continue
		}
		cveIDs = append(cveIDs, s)
		seen[s] = true
	}
	return cveIDs
}
