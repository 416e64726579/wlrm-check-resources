package wapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"wlrm-check-resources/log"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

const wallarmAPI = "api.wallarm.com"

// WallarmAPI represents Wallarm specific attributes.
type WallarmAPI struct {
	APIHost string
	UUID    string
	Secret  string
	Period  interface{}
}

// TelegramAPI represents Telegram specific attributes.
type TelegramAPI struct {
	ChatID int64
	Token  string
}

// DomainsSource represents source of the list of domains.
type DomainsSource struct {
	SourceMeans string
	FilePath    string
	SheetsID    string
	SheetsRange string
	JWTCreds    string
	GDocsCreds  string
	GDocsToken  string
}

// Client for generic purpose.
type Client struct {
	*WallarmAPI
	*TelegramAPI
	*http.Client
	*DomainsSource
	IP        string
	Domain    []string
	Path      []string
	Tokens    []string
	URLStatus map[string][]int
	URLToken  map[string]string
}

// ChannelResp for syncronization necessary data between gorutines
type ChannelResp struct {
	Token    string
	Domain   string
	Path     string
	Status   int
	Body     []byte
	URLToken map[string]string
}

// StructuredResp as a container for result processing
type StructuredResp struct {
	Domains      []string
	Statuses     []int
	WallarmModes []string
	AttackIDs    []string
	HitIDs       []string
}

// SearchReq is a JSON body for a request time range
type SearchReq struct {
	Query    string `json:"query"`
	ClientID []int  `json:"clientid,omitempty"`
	TimeZone string `json:"time_zone,omitempty"`
}

// SearchResp is a JSON response body of the /v1/search endpoint (Wallarm API)
type SearchResp struct {
	Status int `json:"status"`
	Body   struct {
		Vulns   interface{} `json:"vulns"`
		Attacks struct {
			VulnID    interface{}     `json:"vulnid"`
			NotVulnID interface{}     `json:"!vulnid"`
			Path      string          `json:"path"`
			Type      []string        `json:"type"`
			NotType   []string        `json:"!type"`
			Time      [][]interface{} `json:"time"`
			State     string          `json:"!state"`
		} `json:"attacks"`
		Incidents struct {
			VulnID    interface{}     `json:"vulnid"`
			NotVulnID interface{}     `json:"!vulnid"`
			Path      string          `json:"path"`
			Type      []string        `json:"type"`
			NotType   []string        `json:"!type"`
			Time      [][]interface{} `json:"time"`
			State     string          `json:"!state"`
		} `json:"incidents"`
		Testruns interface{} `json:"testruns"`
	} `json:"body"`
}

// FilterReq is a `filter` struct of a JSON body for `attacks` and `hits` endpoints
type FilterReq struct {
	ClientID        []int           `json:"clientid,omitempty"`
	VulnID          interface{}     `json:"vulnid,omitempty"`
	Path            []string        `json:"path,omitempty"`
	Type            []string        `json:"type,omitempty"`
	NotType         []string        `json:"!type,omitempty"`
	Domain          []string        `json:"domain,omitempty"`
	IP              string          `json:"ip,omitempty"`
	Time            [][]interface{} `json:"time,omitempty"`
	State           string          `json:"state,omitempty"`
	NotState        string          `json:"!state,omitempty"`
	NotExperimental bool            `json:"!experimental,omitempty"`
	AttackID        []string        `json:"attackid,omitempty"`
}

// AttackReq is a JSON body for a request attacks
type AttackReq struct {
	*FilterReq `json:"filter"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
	OrderBy    string `json:"order_by,omitempty"`
	OrderDesc  bool   `json:"order_desc,omitempty"`
}

// AttackResp is a JSON response body of the /v1/objects/attack endpoint (Wallarm API)
type AttackResp struct {
	Status int `json:"status"`
	Body   []struct {
		ID           []string    `json:"id"`
		Attackid     string      `json:"attackid"`
		Clientid     int         `json:"Clientid"`
		Domain       string      `json:"domain"`
		Method       string      `json:"method"`
		Parameter    string      `json:"parameter"`
		Path         string      `json:"path"`
		Type         string      `json:"type"`
		FirstTime    int         `json:"first_time"`
		LastTime     int         `json:"last_time"`
		Hits         int         `json:"hits"`
		IPCount      int         `json:"ip_count"`
		Statuscodes  []int       `json:"statuscodes"`
		Experimental interface{} `json:"experimental"`
		BlockStatus  string      `json:"block_status"`
		State        interface{} `json:"state"`
	} `json:"body"`
}

// AttackCountResp is a JSON body for the number of attacks
type AttackCountResp struct {
	Status int `json:"status"`
	Body   struct {
		Attacks int `json:"attacks"`
		Hits    int `json:"hits"`
		Ips     int `json:"ips"`
	} `json:"body"`
}

// HitReq is a JSON body for a request hits
type HitReq struct {
	*FilterReq `json:"filter"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
	OrderBy    string `json:"order_by,omitempty"`
	OrderDesc  bool   `json:"order_desc,omitempty"`
	Points     int    `json:"points,omitempty"`
}

// HitResp is a JSON response body of the /v1/objects/hit endpoint (Wallarm API)
type HitResp struct {
	Status int `json:"status"`
	Body   []struct {
		ID            []string    `json:"id"`
		IP            string      `json:"ip"`
		Size          int         `json:"size"`
		Statuscode    int         `json:"statuscode"`
		Time          int         `json:"time"`
		Value         string      `json:"value"`
		Impression    interface{} `json:"impression"`
		Stamps        []int       `json:"stamps"`
		StampsHash    int         `json:"stamps_hash"`
		ResponseTime  int         `json:"response_time"`
		RemoteCountry string      `json:"remote_country"`
		Point         []string    `json:"point"`
		RemotePort    int         `json:"remote_port"`
		PoolID        int         `json:"poolid"`
		IPBlocked     bool        `json:"ip_blocked"`
		Experimental  interface{} `json:"experimental"`
		AttackID      []string    `json:"attackid"`
		BlockStatus   string      `json:"block_status"`
		RequestID     interface{} `json:"request_id"`
		Datacenter    string      `json:"datacenter"`
		ProxyType     interface{} `json:"proxy_type"`
		Tor           string      `json:"tor"`
		State         interface{} `json:"state"`
	} `json:"body"`
}

// HitCountResp is a JSON body for  the number of hits
type HitCountResp struct {
	Status int `json:"status"`
	Body   struct {
		All      []int `json:"all"`
		Filtered []int `json:"filtered"`
	} `json:"body"`
}

// DetailsResp is a JSON response body of the /v2/hit/details endpoint (Wallarm API)
type DetailsResp struct {
	Status int `json:"status"`
	Body   struct {
		RemoteAddr string `json:"remote_addr"`
		RemotePort string `json:"remote_port"`
		ServerAddr string `json:"server_addr"`
		ServerPort string `json:"server_port"`
		Method     string `json:"method"`
		Proto      string `json:"proto"`
		URI        string `json:"uri"`
		Headers    struct {
			HOST        []string `json:"HOST"`
			USERAGENT   []string `json:"USER-AGENT"`
			CONTENTTYPE []string `json:"CONTENT-TYPE"`
			SCRIPTTOKEN []string `json:"SCRIPT-TOKEN"`
			XWLRMCHECK  []string `json:"X-WLRM-CHECK"`
		} `json:"headers"`
		Body     interface{} `json:"body"`
		NodeUUID string      `json:"node_uuid"`
	} `json:"body"`
}

// NewClient returns a default client object.
func NewClient(uuid, secret, telegramToken string, chatID int64) *Client {
	return &Client{
		Client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				MaxIdleConns:       200,
				IdleConnTimeout:    5 * time.Second,
				DisableCompression: true,
				Dial: (&net.Dialer{
					Timeout: 5 * time.Second,
				}).Dial,
				TLSHandshakeTimeout: 5 * time.Second,
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: time.Second * 10},
		WallarmAPI: &WallarmAPI{
			APIHost: wallarmAPI,
			UUID:    uuid,
			Secret:  secret,
		},
		DomainsSource: &DomainsSource{},
		URLToken:      make(map[string]string),
		URLStatus:     make(map[string][]int),
		TelegramAPI: &TelegramAPI{
			Token:  telegramToken,
			ChatID: chatID,
		},
	}
}

// newRequest is to substitute onto Request with context and extra headers
func (c *Client) newRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Add("User-Agent", "Wallarm-Check-Resources")
	req.Header.Add("Content-Type", "application/json")
	return req, nil
}

// RequestTarget to request either a regular http endpoint
func (c *Client) RequestTarget(ctx context.Context, method, domain string, malicious bool, wg *sync.WaitGroup, ch chan<- ChannelResp) (int, []byte) {
	var (
		res    *http.Response
		status int
		body   []byte
		token  string
	)

	sum := sha256.Sum256([]byte("Wallarm-Check-Resources" + domain + strconv.FormatInt(time.Now().Unix(), 10)))
	token = hex.EncodeToString(sum[:])

	if wg != nil {
		defer wg.Done()
	}

	u, err := url.Parse(domain)
	if err != nil {
		log.G(ctx).Fatal(err)
	}

	switch u.Scheme {
	case "wss", "ws":

		headers := http.Header{
			"User-Agent":   {"Wallarm-Check-Resources"},
			"Content-Type": {"application/json"},
			"Script-Token": {token},
			"X-WLRM-CHECK": {`<details/open/ontoggle="self['wind'%2b'ow']['one'%2b'rror']=self['wind'%2b'ow']['ale'%2b'rt'];throw/**/self['doc'%2b'ument']['domain'];">`},
		}
		ws, _, err := websocket.DefaultDialer.Dial(u.String(), headers)
		if err != nil {
			log.G(ctx).Fatal(err)
		}
		defer ws.Close()

		wsPayload := map[string]interface{}{
			"user": `<body onhashchange="alert(1)">`,
		}
		data, err := json.Marshal(wsPayload)
		if err != nil {
			log.G(ctx).Fatal(err)
		}
		ws.WriteJSON(data)

		_, body, err = ws.ReadMessage()
		if err != nil {
			log.G(ctx).Printf("It is okay for some wss connections due to authentication. %s", err)
		}

		if ch != nil {
			fullResp := ChannelResp{
				Token:  token,
				Domain: u.Host,
				Path:   u.Path,
				Status: 101,
				Body:   body}
			ch <- fullResp
		}
		log.G(ctx).Debugf("Sent data to WebSocket with body %s", string(data))

	case "https", "http":

		req, err := c.newRequest(ctx, method, u.String(), nil)
		if err != nil {
			log.G(ctx).Fatal(err)
		}
		if malicious {
			if method == "GET" {
				q := req.URL.Query()
				q.Add("wlrm", "%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64")
				q.Add("wlrm", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%73%68%61%64%6f%77")
				req.URL.RawQuery = q.Encode()
				req.Header.Add("X-WLRM-CHECK", `<a onkeydown="alert(1)" contenteditable>test</a>`)
			} else {
				payload := []byte(`"user": "Y3VybCAnaHR0cDovL2xvY2FsaG9zdDo4MDgxL2NoZWNrVmFsaWQnIC1IICdBdXRob3JpemF0aW9uOiAnICAtLWRhdGEgJ2RvY3VtZW50PXRoaXMuY29uc3RydWN0b3IuY29uc3RydWN0b3IoInJldHVybiBwcm9jZXNzIikoKS5tYWluTW9kdWxlLnJlcXVpcmUoImNoaWxkX3Byb2Nlc3MiKS5leGVjU3luYygiL0FwcGxpY2F0aW9ucy9DYWxjdWxhdG9yLmFwcC9Db250ZW50cy9NYWNPUy9DYWxjdWxhdG9yIikn",
                        "password": "%53%45%4c%45%43%54%20%43%4f%4e%43%41%54%28%43%48%41%52%28%37%35%29%2c%43%48%41%52%28%37%36%29%2c%43%48%41%52%28%37%37%29%29",
                        "cvv": "%53%45%4c%45%43%54%20%4c%4f%41%44%5f%46%49%4c%45%28%30%78%36%33%33%41%35%43%36%32%36%46%36%46%37%34%32%45%36%39%36%45%36%39%29"`)
				req, err = c.newRequest(ctx, method, u.String(), bytes.NewBuffer(payload))
				if err != nil {
					log.G(ctx).Fatal(err)
				}
			}
			req.Header.Add("Script-Token", token)
		} else {
			req.Header.Del("User-Agent")
			req.Header.Del("Content-Type")
			req.Header.Del("Script-Token")
		}
		retries := 3
		for retries > 0 {
			res, err = c.Do(req)
			if err != nil {
				log.G(ctx).Println(err)
				retries--
				if retries == 0 {
					log.G(ctx).Fatalf("The request %s failed three times with the error %s", req.URL, err)
				}
			} else {
				break
			}
			if res != nil {
				defer res.Body.Close()
			}
		}

		if res != nil {
			status = res.StatusCode
			body, err = ioutil.ReadAll(res.Body)
			if err != nil {
				log.G(ctx).Fatal(err)
			}
		}
		if ch != nil {
			fullResp := ChannelResp{
				Token:  token,
				Domain: u.Host,
				Path:   u.Path,
				Status: status,
				Body:   body}
			ch <- fullResp
		}
		log.G(ctx).Debugf("Sent data to %s", req.URL)
	default:
		log.G(ctx).Fatal("Specify scheme (https://, http://, wss://, ws:// in the domain file")
	}

	log.G(ctx).Println("Sent data to", string(u.Host))

	return status, body
}

// RequestSearchTime to request a search time string in Unix (from Wallarm API)
func (c *Client) RequestSearchTime(ctx context.Context, payload *SearchReq) {
	var res *http.Response

	if c.APIHost == "" {
		c.APIHost = wallarmAPI
	}

	method := "POST"
	url := fmt.Sprintf("https://%s:444/v1/search", c.APIHost)
	jsonbody, err := json.Marshal(payload)
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req, err := c.newRequest(ctx, method, url, bytes.NewBuffer(jsonbody))
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req.Header.Add("X-WallarmAPI-UUID", c.UUID)
	req.Header.Add("X-WallarmAPI-Secret", c.Secret)

	retries := 3
	for retries > 0 {
		res, err = c.Do(req)
		if err != nil {
			log.G(ctx).Println(err)
			retries--
			if retries == 0 {
				log.G(ctx).Fatalf("The request %s failed three times with the error %s", req.URL, err)
			}
		} else {
			break
		}
	}

	if res != nil {
		defer res.Body.Close()
		status := res.StatusCode
		body, err := ioutil.ReadAll(res.Body)

		log.G(ctx).Debugf("Request:%v\nResponse status: %d\nResponse Body:%s\n", req, res.StatusCode, string(body))

		if err != nil {
			log.G(ctx).Fatal(err)
		}
		if body != nil && status == 200 {
			var data SearchResp
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			c.Period = data.Body.Attacks.Time[0][0]
		} else {
			var data interface{}
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			log.G(ctx).Fatalf("Status code: %d\nBody: %v", status, data)
		}
	}
}

// RequestAttackCount to request the amount of attacks (from Wallarm API)
func (c *Client) RequestAttackCount(ctx context.Context, payload *AttackReq) int {
	var (
		res         *http.Response
		attackCount int
	)

	if c.APIHost == "" {
		c.APIHost = wallarmAPI
	}

	method := "POST"
	url := fmt.Sprintf("https://%s:444/v1/objects/attack/count", c.APIHost)
	jsonbody, err := json.Marshal(payload)
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req, err := c.newRequest(ctx, method, url, bytes.NewBuffer(jsonbody))
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req.Header.Add("X-WallarmAPI-UUID", c.UUID)
	req.Header.Add("X-WallarmAPI-Secret", c.Secret)

	retries := 3
	for retries > 0 {
		res, err = c.Do(req)
		if err != nil {
			log.G(ctx).Println(err)
			retries--
			if retries == 0 {
				log.G(ctx).Fatalf("The request %s failed three times with the error %s", req.URL, err)
			}
		} else {
			break
		}
	}

	if res != nil {
		defer res.Body.Close()
		status := res.StatusCode
		body, err := ioutil.ReadAll(res.Body)

		log.G(ctx).Debugf("Request:%v\nResponse status: %d\nResponse Body:%s\n", req.URL, res.StatusCode, string(body))

		if err != nil {
			log.G(ctx).Fatal(err)
		}

		if body != nil && status == 200 {

			var data AttackCountResp
			if err := json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			attackCount = data.Body.Attacks
		} else {
			var data interface{}
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			log.G(ctx).Fatalf("Status code: %d\nBody: %v", status, data)
		}
	}
	return attackCount
}

// RequestAttacks to request an attackIDs (from Wallarm API)
func (c *Client) RequestAttacks(ctx context.Context, payload *AttackReq) StructuredResp {

	var (
		exportedDomains, exportedModes, exportedAttackids []string
		exportedStatuses                                  []int
		res                                               *http.Response
	)

	if c.APIHost == "" {
		c.APIHost = wallarmAPI
	}

	method := "POST"
	url := fmt.Sprintf("https://%s:444/v1/objects/attack", c.APIHost)
	jsonbody, err := json.Marshal(payload)
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req, err := c.newRequest(ctx, method, url, bytes.NewBuffer(jsonbody))
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req.Header.Add("X-WallarmAPI-UUID", c.UUID)
	req.Header.Add("X-WallarmAPI-Secret", c.Secret)

	retries := 3
	for retries > 0 {
		res, err = c.Do(req)
		if err != nil {
			log.G(ctx).Println(err)
			retries--
			if retries == 0 {
				log.G(ctx).Fatalf("The request %s failed three times with the error %s", req.URL, err)
			}
		} else {
			break
		}
	}

	if res != nil {
		defer res.Body.Close()
		status := res.StatusCode
		body, err := ioutil.ReadAll(res.Body)

		log.G(ctx).Debugf("Request:%v\nResponse status: %d\nResponse Body:%s\n", req.URL, res.StatusCode, string(body))

		if err != nil {
			log.G(ctx).Fatal(err)
		}

		if body != nil && status == 200 {

			var data AttackResp
			if err := json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			for _, key := range data.Body {
				domain := key.Domain
				mode := key.BlockStatus
				attackid := key.ID
				exportedDomains = append(exportedDomains, domain)
				exportedStatuses = append(exportedStatuses, status)
				exportedModes = append(exportedModes, mode)
				exportedAttackids = append(exportedAttackids, attackid...)
			}
		} else {
			var data interface{}
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			log.G(ctx).Fatalf("Status code: %d\nBody: %v", status, data)
		}
	}
	attacksResp := StructuredResp{
		Domains:      exportedDomains,
		Statuses:     exportedStatuses,
		WallarmModes: exportedModes,
		AttackIDs:    exportedAttackids,
	}
	return attacksResp
}

// RequestHitCount to request the number of hits in an attack (from Wallarm API)
func (c *Client) RequestHitCount(ctx context.Context, payload *HitReq) int {
	var (
		res *http.Response
		sum int
	)

	if c.APIHost == "" {
		c.APIHost = wallarmAPI
	}
	method := "POST"
	url := fmt.Sprintf("https://%s:444/v1/objects/attack/hit_count", c.APIHost)
	jsonbody, err := json.Marshal(payload)
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req, err := c.newRequest(ctx, method, url, bytes.NewBuffer(jsonbody))
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req.Header.Add("X-WallarmAPI-UUID", c.UUID)
	req.Header.Add("X-WallarmAPI-Secret", c.Secret)

	retries := 3
	for retries > 0 {
		res, err = c.Do(req)
		if err != nil {
			log.G(ctx).Println(err)
			retries--
			if retries == 0 {
				log.G(ctx).Fatalf("The request %s failed three times with the error %s", req.URL, err)
			}
		} else {
			break
		}
	}

	if res != nil {
		defer res.Body.Close()
		status := res.StatusCode
		body, err := ioutil.ReadAll(res.Body)

		log.G(ctx).Debugf("Request:%v\nResponse status: %d\nResponse Body:%s\n", req, res.StatusCode, string(body))

		if err != nil {
			log.G(ctx).Fatal(err)
		}

		if body != nil && status == 200 {
			var data HitCountResp
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			for _, key := range data.Body.All {
				sum += key
			}
		} else {
			var data interface{}
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			log.G(ctx).Fatalf("Status code: %d\nBody: %v", status, data)
		}
	}

	return sum
}

// RequestHits to request all hits related to attacks (from Wallarm API)
func (c *Client) RequestHits(ctx context.Context, payload *HitReq, wg *sync.WaitGroup, attackIDs chan<- []string) {
	var res *http.Response

	if wg != nil {
		defer wg.Done()
	}

	if c.APIHost == "" {
		c.APIHost = wallarmAPI
	}
	var concatID []string
	method := "POST"
	url := fmt.Sprintf("https://%s:444/v1/objects/hit", c.APIHost)
	jsonbody, err := json.Marshal(payload)
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req, err := c.newRequest(ctx, method, url, bytes.NewBuffer(jsonbody))
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	req.Header.Add("X-WallarmAPI-UUID", c.UUID)
	req.Header.Add("X-WallarmAPI-Secret", c.Secret)

	retries := 3
	for retries > 0 {
		res, err = c.Do(req)
		if err != nil {
			log.G(ctx).Println(err)
			retries--
			if retries == 0 {
				log.G(ctx).Fatalf("The request %s failed three times with the error %s", req.URL, err)
			}
		} else {
			break
		}
	}

	if res != nil {
		defer res.Body.Close()
		status := res.StatusCode
		body, err := ioutil.ReadAll(res.Body)

		log.G(ctx).Debugf("Request:%v\nResponse status: %d\nResponse Body:%s\n", req, res.StatusCode, string(body))

		if err != nil {
			log.G(ctx).Fatal(err)
		}

		if body != nil && status == 200 {
			var data HitResp
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			for _, key := range data.Body {
				unixTimeUTC := time.Unix(int64(key.Time), 0)
				if (unixTimeUTC.Unix()) >= int64(c.Period.(float64)) {
					ID := key.ID
					concatID = append(concatID, ID...)
				} else {
					// They are sorted by time
					break
				}
			}
		} else {
			var data interface{}
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			log.G(ctx).Fatalf("Status code: %d\nBody: %v", status, data)
		}
	}

	if attackIDs != nil {
		attackIDs <- concatID
	}
}

// RequestDetails to request all details from hits in order to find a relevant header (from Wallarm API)
func (c *Client) RequestDetails(ctx context.Context, params string, tokenChan chan<- []string) []string {
	var (
		res   *http.Response
		token []string
	)

	if c.APIHost == "" {
		c.APIHost = wallarmAPI
	}
	method := "GET"
	url := fmt.Sprintf("https://%s:444/v2/hit/details", c.APIHost)
	req, err := c.newRequest(ctx, method, url, nil)
	if err != nil {
		log.G(ctx).Fatal(err)
	}
	q := req.URL.Query()
	q.Add("id", params)
	req.URL.RawQuery = q.Encode()
	req.Header.Del("Content-Type")
	req.Header.Add("X-WallarmAPI-UUID", c.UUID)
	req.Header.Add("X-WallarmAPI-Secret", c.Secret)

	retries := 3
	for retries > 0 {
		res, err = c.Do(req)
		if err != nil {
			log.G(ctx).Println(err)
			retries--
			if retries == 0 {
				log.G(ctx).Fatalf("The request %s failed three times with the error %s", req.URL, err)
			}
		} else {
			break
		}
	}

	if res != nil {
		defer res.Body.Close()
		status := res.StatusCode
		body, err := ioutil.ReadAll(res.Body)

		log.G(ctx).Debugf("Request:%v\nResponse status: %d\nResponse Body:%s\n", req, res.StatusCode, string(body))

		if err != nil {
			log.G(ctx).Fatal(err)
		}

		if body != nil && status == 200 {
			var data DetailsResp
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			token = data.Body.Headers.SCRIPTTOKEN
		} else {
			var data interface{}
			if err = json.Unmarshal([]byte(body), &data); err != nil {
				log.G(ctx).Fatal(err)
			}
			log.G(ctx).Fatalf("Status code: %d\nBody: %v", status, data)
		}
	}

	tokenChan <- token
	return token
}

// SendToTelegram to send results to Telegram messenger
func (c *Client) SendToTelegram(ctx context.Context, message string, finished chan<- bool) {
	bot, err := tgbotapi.NewBotAPI(c.Token)
	if err != nil {
		if strings.HasSuffix(err.Error(), ": i/o timeout") {
			dialSocksProxy, err := proxy.SOCKS5("tcp", "95.110.194.245:55402", nil, proxy.Direct)
			if err != nil {
				log.G(ctx).Fatal("Error connecting to proxy:", err)
			}
			tr := &http.Transport{Dial: dialSocksProxy.Dial}
			clientBot := &http.Client{Transport: tr}
			bot, err = tgbotapi.NewBotAPIWithClient(c.Token, clientBot)
			if err != nil {
				log.G(ctx).Fatal("Error connecting to proxy:", err)
			}
		} else {
			log.G(ctx).Fatal(err)
		}
	}
	if log.G(ctx).Logger.GetLevel() == logrus.DebugLevel {
		bot.Debug = true
	}

	pepeMeme := "CAACAgQAAxkBAAOyXpQOg5330adAWZ9LBbudUgUsqz0AAjYBAAKoISEG7PSIb0-MkyoYBA"
	questionMeme := "CAACAgIAAxkBAAO4XpQSZhP5lcpFnkvfUAowvHfP2uQAAqhWAAKezgsAASwZD-0JhvvMGAQ"
	msg := tgbotapi.NewMessage(c.ChatID, message)
	// msg.ParseMode = "markdown"

	m := msg
	for len(msg.Text) > 4096 {
		lastNewLine := strings.LastIndex(msg.Text[:4096], "\n")
		m.Text = msg.Text[:lastNewLine]
		_, err = bot.Send(m)
		if err != nil {
			log.G(ctx).Fatal(err)
		}
		msg.Text = msg.Text[lastNewLine:]
	}
	if len(msg.Text) <= 4096 {
		_, err = bot.Send(msg)
		if err != nil {
			log.G(ctx).Fatal(err)
		}
	}

	if strings.Contains(message, "detected") {
		stick := tgbotapi.NewStickerShare(c.ChatID, pepeMeme)
		_, err := bot.Send(stick)
		if err != nil {
			log.G(ctx).Fatal(err)
		}
	} else {
		stick := tgbotapi.NewStickerShare(c.ChatID, questionMeme)
		_, err := bot.Send(stick)
		if err != nil {
			log.G(ctx).Fatal(err)
		}
	}
	message = strings.Replace(message, "`", "", -1)
	log.G(ctx).Println(message)
	log.G(ctx).Printf("Authorized and sent to the bot")

	finished <- true
}
