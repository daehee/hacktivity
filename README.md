# hacktivity [![Go Report](https://goreportcard.com/badge/github.com/daehee/hacktivity)](https://goreportcard.com/report/github.com/daehee/hacktivity)

Go library for fetching HackerOne Hacktivity reports.

## Install

```
go get github.com/daehee/hacktivity
```

## Usage

The `hacktivity` package provides a `Client` for fetching Hacktivity reports:
```go
// Init hacktivity client
client := NewClient()

// Get the 100 most recent Hacktivity reports
urls, err := client.GetLatestReports(100)

// Fetch a Hacktivity report by URL
hacktivity, err := client.GetHacktivity("https://hackerone.com/reports/1019891")
```

Returns API response as `Hacktivity` struct:
```go
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
```

## License

[MIT License](LICENSE)