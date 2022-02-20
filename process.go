// +build linux darwin

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"wlrm-check-resources/gdocs"
	"wlrm-check-resources/helpers"
	"wlrm-check-resources/log"
	"wlrm-check-resources/wapi"

	"github.com/sirupsen/logrus"
	"google.golang.org/api/sheets/v4"
)

// cliParams represents actual params passed through the command line.
type cliParams struct {
	uuid, secret, telegramToken string
	chatID                      int64
}

var (
	method             string
	clientID, duration int
)

func getTime() (zone string) {
	t := time.Now()
	zone, _ = t.Zone()
	return
}

func getMyIP(ctx context.Context, c *wapi.Client) {
	_, ipAddress := c.RequestTarget(ctx, "GET", "http://ifconfig.me/ip", false, nil, nil)
	c.IP = string(ipAddress)
	c.IP = strings.TrimSuffix(c.IP, "\n")
}

func attackTargetFile(ctx context.Context, c *wapi.Client) (respChan chan wapi.ChannelResp) {
	var (
		domains []string
		wg      sync.WaitGroup
	)
	if err := helpers.ReadDomainsFile(&c.FilePath, &domains); err != nil {
		log.G(ctx).Fatal(err)
	}

	respChan = make(chan wapi.ChannelResp, len(domains))
	for _, domain := range domains {
		wg.Add(2)
		go c.RequestTarget(ctx, method, domain, true, &wg, respChan)
		if method == "POST" || method == "PUT" {
			go c.RequestTarget(ctx, "GET", domain, true, &wg, respChan)
		} else {
			go c.RequestTarget(ctx, "POST", domain, true, &wg, respChan)
		}
	}
	wg.Wait()
	close(respChan)
	return
}

func attackTargetGDocs(ctx context.Context, c *wapi.Client) (respChan chan wapi.ChannelResp) {
	var (
		domains []string
		wg      sync.WaitGroup
		srv     *sheets.Service
	)

	switch {
	case c.GDocsCreds != "" && c.GDocsToken != "":
		// This is used for Apps with access to your account.
		// It requires token.json, otherwise it will ask you to approve via a browser
		srv = gdocs.GiveServiceApp(c.GDocsCreds, c.GDocsToken)
	case c.JWTCreds != "":
		// This is used for service accounts
		srv = gdocs.GiveServiceAccount(c.JWTCreds)
	default:
		log.G(ctx).Fatalf("No authentication method for Goodle Docs set. Should be either jwt or appCreds with token")
	}

	spreadsheetID := c.SheetsID
	readRange := c.SheetsRange
	resp, err := srv.Spreadsheets.Values.Get(spreadsheetID, readRange).Do()
	if err != nil {
		log.G(ctx).Fatalf("Unable to retrieve data from sheet: %v", err)
	}

	if len(resp.Values) == 0 {
		fmt.Println("No data found.")
	} else {
		for _, row := range resp.Values {
			if row[0] != "" {
				d := fmt.Sprintf("%v", row[0])
				domains = append(domains, d)
			}
		}
	}
	length := 2 * len(domains)
	respChan = make(chan wapi.ChannelResp, length)
	for _, domain := range domains {
		wg.Add(2)
		go c.RequestTarget(ctx, method, domain, true, &wg, respChan)
		if method == "POST" || method == "PUT" {
			go c.RequestTarget(ctx, "GET", domain, true, &wg, respChan)
		} else {
			go c.RequestTarget(ctx, "POST", domain, true, &wg, respChan)
		}
	}
	wg.Wait()
	close(respChan)
	return
}

func fillClientFields(ctx context.Context, c *wapi.Client, respChan <-chan wapi.ChannelResp) {
	for res := range respChan {
		c.Domain = append(c.Domain, res.Domain)
		regexPath := fmt.Sprintf("*%s", res.Path)

		// Append if element NOT exists in the path slice
		// Linear search in order to not sort the slice many times in loop (for binary search)
		if !helpers.Contains(regexPath, c.Path) {
			c.Path = append(c.Path, regexPath)
		}
		c.Tokens = append(c.Tokens, res.Token)
		c.URLToken[res.Token] = res.Domain
		if val, ok := c.URLStatus[res.Domain]; ok {
			c.URLStatus[res.Domain] = append(val, res.Status)
		} else {
			c.URLStatus[res.Domain] = []int{res.Status}
		}
	}
	log.G(ctx).Debugf("Query with the following parameters Paths: %s, IP: %s, Domains: %s", c.Path, c.IP, c.Domain)
}

func makeSearchRequest(ctx context.Context, c *wapi.Client) {
	search := &wapi.SearchReq{
		Query:    "attacks last 1 hour !falsepositive",
		ClientID: []int{clientID},
		TimeZone: getTime(),
	}
	c.RequestSearchTime(ctx, search)
}

func makeAttackRequest(ctx context.Context, c *wapi.Client) (attacksResp wapi.StructuredResp) {
	attack := &wapi.AttackReq{
		FilterReq: &wapi.FilterReq{
			ClientID: []int{clientID},
			VulnID:   nil,
			NotType:  []string{"warn"},
			Time:     [][]interface{}{{c.Period, nil}},
			Domain:   c.Domain,
			Path:     c.Path,
			IP:       c.IP,
			NotState: "falsepositive",
		},
		Limit:     1000,
		Offset:    0,
		OrderBy:   "last_time",
		OrderDesc: true,
	}
	attackCount := &wapi.AttackReq{
		FilterReq: &wapi.FilterReq{
			ClientID: []int{clientID},
			VulnID:   nil,
			NotType:  []string{"warn"},
			Time:     [][]interface{}{{c.Period, nil}},
			Domain:   c.Domain,
			Path:     c.Path,
			IP:       c.IP,
			NotState: "falsepositive",
		},
	}

	attacksResp = c.RequestAttacks(ctx, attack)
	log.G(ctx).Println("Started making a /v1/objects/attack/count request")
	count := c.RequestAttackCount(ctx, attackCount)
	realCount := len(attacksResp.AttackIDs) / 2

	log.G(ctx).Printf("The number from count endpoint: %d\n The number from attack endpoint: %d", count, realCount)

	for count > realCount {
		attack.Offset += 1000
		attacksTempResp := c.RequestAttacks(ctx, attack)
		attacksResp.AttackIDs = append(attacksResp.AttackIDs, attacksTempResp.AttackIDs...)
		realCount += len(attacksTempResp.AttackIDs)
	}
	return attacksResp
}

func makeHitRequest(ctx context.Context, c *wapi.Client, hitIDS chan<- []string, attacksResp wapi.StructuredResp) {
	var waitHits sync.WaitGroup
	for i := 0; i < len(attacksResp.AttackIDs); i += 2 {
		hits := &wapi.HitReq{
			FilterReq: &wapi.FilterReq{
				ClientID:        []int{clientID},
				NotType:         []string{"warn", "marker"},
				Time:            [][]interface{}{{c.Period, nil}},
				NotExperimental: true,
				AttackID:        []string{attacksResp.AttackIDs[i], attacksResp.AttackIDs[i+1]},
				NotState:        "falsepositive",
			},
			Limit:     1000,
			Offset:    0,
			OrderBy:   "time",
			OrderDesc: true,
		}
		waitHits.Add(1)
		go c.RequestHits(ctx, hits, &waitHits, hitIDS)
	}
	waitHits.Wait()
	close(hitIDS)
}

func makeDetailsRequest(ctx context.Context, c *wapi.Client, hitIDS <-chan []string) (tokensSlice []string) {

	tokenChan := make(chan []string, 10)
	for {
		hit, opened := <-hitIDS
		if !opened {
			break
		}
		for i := 0; i < len(hit); i += 2 {
			id := fmt.Sprintf("%s:%s", hit[i], hit[i+1])
			go c.RequestDetails(ctx, id, tokenChan)
		}

		// Blocking to iterate over unclosed channel without WaitGroup
		for i := 0; i < len(hit); i += 2 {
			token := <-tokenChan
			tokensSlice = append(tokensSlice, token...)
		}
	}
	return tokensSlice
}

func findDiffToken(c *wapi.Client, tokensSlice []string) (diff string) {
	sort.Strings(c.Tokens)
	sort.Strings(tokensSlice)
	diffStr := helpers.DifferenceSlices(c.Tokens, tokensSlice)
	var urls []string
	for _, t := range diffStr {
		urls = append(urls, c.URLToken[t])
	}

	unique := helpers.RemoveDuplicate(urls)
	for _, u := range unique {
		status := c.URLStatus[u]
		diff = fmt.Sprintf("%sURL domain: %s\nStatus codes: %d\n", diff, u, status)
	}
	return
}

func makeTelegramRequest(ctx context.Context, c *wapi.Client, diff *string) {
	finished := make(chan bool)
	if *diff == "" {
		go c.SendToTelegram(ctx, "Everything for the client was exported and detected timely", finished)
	} else {
		go c.SendToTelegram(ctx, *diff, finished)
	}
	<-finished
}

func run(ctx context.Context, c *wapi.Client) {

	log.G(ctx).Printf("Obtaining the current IP address...")
	getMyIP(ctx, c)

	var respChan chan wapi.ChannelResp
	if c.SourceMeans == "gdocs" {
		respChan = attackTargetGDocs(ctx, c)
	} else {
		respChan = attackTargetFile(ctx, c)
	}

	fillClientFields(ctx, c, respChan)

	log.G(ctx).Printf("Wait for %d seconds...", duration)
	time.Sleep(time.Duration(duration) * time.Second)

	log.G(ctx).Println("Started making a /v1/search request")
	makeSearchRequest(ctx, c)

	log.G(ctx).Println("Started making a /v1/objects/attack request")
	attacksResp := makeAttackRequest(ctx, c)

	log.G(ctx).Println("Started making /v1/objects/hit requests")
	hitIDS := make(chan []string, len(attacksResp.AttackIDs)/2)
	makeHitRequest(ctx, c, hitIDS, attacksResp)

	log.G(ctx).Println("Started making /v2/hit/details requests")
	tokensSlice := makeDetailsRequest(ctx, c, hitIDS)

	log.G(ctx).Println("Check distinction between two slices of tokens")
	diff := findDiffToken(c, tokensSlice)
	makeTelegramRequest(ctx, c, &diff)
}

func checkEnv() (context.Context, *cliParams) {
	logger := logrus.New()
	ctx := context.Background()

	wallarmAPI := os.Getenv("WALLARM_API_HOST")
	uuid := os.Getenv("WALLARM_UUID")
	secret := os.Getenv("WALLARM_SECRET")
	telegramToken := os.Getenv("TELEGRAM_TOKEN")
	chatIDString := os.Getenv("CHAT_ID")
	logLevel := os.Getenv("LOG_LEVEL")

	switch {
	case uuid == "":
		log.G(ctx).Fatalf("Environment variable WALLARM_UUID of type %T is not set", uuid)
	case secret == "":
		log.G(ctx).Fatalf("Environment variable WALLARM_SECRET of type %T is not set", secret)
	case telegramToken == "":
		log.G(ctx).Fatalf("Environment variable TELEGRAM_TOKEN of type %T is not set", telegramToken)
	case chatIDString == "":
		log.G(ctx).Fatalf("Environment variable CHAT_ID of type %T is not set", chatIDString)
	case wallarmAPI == "":
		wallarmAPI = "api.wallarm.com"
	}

	var err error
	chatID, err := strconv.ParseInt(chatIDString, 10, 64)
	if err != nil {
		log.G(ctx).Printf("%d of type %T", chatID, chatID)
	}

	switch strings.ToUpper(logLevel) {
	case "DEBUG":
		logger.SetLevel(logrus.DebugLevel)
	case "INFO":
		logger.SetLevel(logrus.InfoLevel)
	default:
		logger.SetLevel(logrus.ErrorLevel)
	}
	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.JSONFormatter{})

	logEntry := logger.WithContext(ctx)
	ctx = log.WithLogger(ctx, logEntry)

	params := cliParams{
		uuid:          uuid,
		secret:        secret,
		telegramToken: telegramToken,
		chatID:        chatID,
	}

	return ctx, &params
}
