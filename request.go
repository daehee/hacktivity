package hacktivity

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/valyala/fastjson"
)

type Client struct {
	hc *http.Client
	parserPool *fastjson.ParserPool
}

func NewClient() *Client {
	return &Client{
		hc: &http.Client{Timeout: 10 * time.Second},
		parserPool: &fastjson.ParserPool{}, // So that json parser can be reused
	}
}

const (
	graphQLBase = "https://hackerone.com/graphql"
	userAgent   = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36"
	// userAgent = Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"
)

func (c *Client) GetLatestReports(reqCount int) ([]string, error) {
	query := `
{"operationName":"HacktivityPageQuery","variables":{"querystring":"","where":{"report":{"disclosed_at":{"_is_null":false}}},"orderBy":null,"secureOrderBy":{"latest_disclosable_activity_at":{"_direction":"DESC"}},"count":%d,"maxShownVoters":10},"query":"query HacktivityPageQuery($querystring: String, $orderBy: HacktivityItemOrderInput, $secureOrderBy: FiltersHacktivityItemFilterOrder, $where: FiltersHacktivityItemFilterInput, $count: Int, $cursor: String, $maxShownVoters: Int) {\n  me {\n    id\n    __typename\n  }\n  hacktivity_items(first: $count, after: $cursor, query: $querystring, order_by: $orderBy, secure_order_by: $secureOrderBy, where: $where) {\n    total_count\n    ...HacktivityList\n    __typename\n  }\n}\n\nfragment HacktivityList on HacktivityItemConnection {\n  total_count\n  pageInfo {\n    endCursor\n    hasNextPage\n    __typename\n  }\n  edges {\n    node {\n      ... on HacktivityItemInterface {\n        id\n        databaseId: _id\n        ...HacktivityItem\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n  __typename\n}\n\nfragment HacktivityItem on HacktivityItemUnion {\n  type: __typename\n  ... on HacktivityItemInterface {\n    id\n    votes {\n      total_count\n      __typename\n    }\n    voters: votes(last: $maxShownVoters) {\n      edges {\n        node {\n          id\n          user {\n            id\n            username\n            __typename\n          }\n          __typename\n        }\n        __typename\n      }\n      __typename\n    }\n    upvoted: upvoted_by_current_user\n    __typename\n  }\n  ... on Undisclosed {\n    id\n    ...HacktivityItemUndisclosed\n    __typename\n  }\n  ... on Disclosed {\n    id\n    ...HacktivityItemDisclosed\n    __typename\n  }\n  ... on HackerPublished {\n    id\n    ...HacktivityItemHackerPublished\n    __typename\n  }\n}\n\nfragment HacktivityItemUndisclosed on Undisclosed {\n  id\n  reporter {\n    id\n    username\n    ...UserLinkWithMiniProfile\n    __typename\n  }\n  team {\n    handle\n    name\n    medium_profile_picture: profile_picture(size: medium)\n    url\n    id\n    ...TeamLinkWithMiniProfile\n    __typename\n  }\n  latest_disclosable_action\n  latest_disclosable_activity_at\n  requires_view_privilege\n  total_awarded_amount\n  currency\n  __typename\n}\n\nfragment TeamLinkWithMiniProfile on Team {\n  id\n  handle\n  name\n  __typename\n}\n\nfragment UserLinkWithMiniProfile on User {\n  id\n  username\n  __typename\n}\n\nfragment HacktivityItemDisclosed on Disclosed {\n  id\n  reporter {\n    id\n    username\n    ...UserLinkWithMiniProfile\n    __typename\n  }\n  team {\n    handle\n    name\n    medium_profile_picture: profile_picture(size: medium)\n    url\n    id\n    ...TeamLinkWithMiniProfile\n    __typename\n  }\n  report {\n    id\n    title\n    substate\n    url\n    __typename\n  }\n  latest_disclosable_action\n  latest_disclosable_activity_at\n  total_awarded_amount\n  severity_rating\n  currency\n  __typename\n}\n\nfragment HacktivityItemHackerPublished on HackerPublished {\n  id\n  reporter {\n    id\n    username\n    ...UserLinkWithMiniProfile\n    __typename\n  }\n  team {\n    id\n    handle\n    name\n    medium_profile_picture: profile_picture(size: medium)\n    url\n    ...TeamLinkWithMiniProfile\n    __typename\n  }\n  report {\n    id\n    url\n    title\n    substate\n    __typename\n  }\n  latest_disclosable_activity_at\n  severity_rating\n  __typename\n}\n"}
`
	req, err := http.NewRequest("POST", graphQLBase, strings.NewReader(fmt.Sprintf(query, reqCount)))
	if err != nil {
		return nil, fmt.Errorf("error initializing http POST request: %v", err)
	}
	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Authority", "hackerone.com")
	req.Header.Add("X-Auth-Token", "----")
	req.Header.Add("Origin", "https://hackerone.com")
	req.Header.Add("Content-Type", "application/json")

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := ioutil.ReadAll(resp.Body)

	parser := c.parserPool.Get()
	defer c.parserPool.Put(parser)
	parsed, err := parser.ParseBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("error parsing graphql response: %v", err)
	}

	var urls []string
	edges := parsed.GetArray("data", "hacktivity_items", "edges")
	for _, edge := range edges {
		reportURL := string(edge.GetStringBytes("node", "report", "url"))
		urls = append(urls, reportURL)
	}
	return urls, nil
}

// GetHacktivity scrapes json endpoint for given HackerOne report URL
// and returns response in Hacktivity struct
func (c *Client) GetHacktivity(u string) (Hacktivity, error) {
	uJSON := fmt.Sprintf("%s.json", u)
	req, err := http.NewRequest(http.MethodGet, uJSON, nil)
	if err != nil {
		return Hacktivity{}, fmt.Errorf("error initializing http GET request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.hc.Do(req)
	if err != nil {
		return Hacktivity{}, err
	}
	defer resp.Body.Close()

	if resp.Body == nil {
		return Hacktivity{}, fmt.Errorf("http response body nil for %s", uJSON)
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return Hacktivity{}, err
	}

	return c.jsonToHacktivity(u, raw)
}
