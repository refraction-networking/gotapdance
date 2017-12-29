package browser

import (
    "github.com/wirepair/gcd"
    "github.com/wirepair/gcd/gcdapi"

    "bytes"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "io/ioutil"
    "log"
    "math"
    "math/rand"
    "net/http"
    "strings"
    "time"
)

var current_url string
var client *http.Client
var overt string

func Browse(overt_host string, http_client *http.Client) {
    var err error

    rand.Seed(time.Now().UnixNano())
    client = http_client
    overt = overt_host

    // TODO: Get platform-specific exePath or use ConnectToInstance
    debugger := gcd.NewChromeDebugger()
    debugger.StartProcess("/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary", "/tmp/", "9222")
    defer debugger.ExitProcess()

    target, err := debugger.NewTab()
    if err != nil { log.Fatalf("Error getting targets: %s\n", err) }

    target.Subscribe("Page.loadEventFired", loadEventFired)

    _, err = target.Page.Enable()
    if err != nil { log.Fatalf("Error getting page: %s\n", err) }

    target.Subscribe("Network.requestIntercepted", requestIntercepted)

    // TODO: Decide if requests made to non-overt hosts should be intercepted
    // TODO: Can this argument be an empty slice?
    _, err = target.Network.SetRequestInterception([]*gcdapi.NetworkRequestPattern{&gcdapi.NetworkRequestPattern{}})
    if err != nil { log.Fatalf("Error setting interception: %s\n", err) }

    current_url = "https://" + overt + "/"
    log.Printf("Navigating to %s\n", current_url)

    _, _, err = target.Page.Navigate(current_url, "", "")
    if err != nil { log.Fatalf("Error navigating to %s: %s\n", current_url, err) }

    select{}
}

func loadEventFired(target *gcd.ChromeTarget, event []byte) {
    var err error

    // TODO: Improve page stay heuristics
    duration := time.Duration(math.Abs(rand.NormFloat64()*2+5) * float64(time.Second))

    log.Printf("Sleeping for %d seconds...\n", int(duration / time.Second))

    time.Sleep(duration)

    dom := target.DOM
    root, err := dom.GetDocument(-1, true)
    if err != nil { log.Fatalf("Error getting root: %s\n", err) }

    links, err := dom.QuerySelectorAll(root.NodeId, "a")
    if err != nil { log.Fatalf("Error getting links: %s\n", err) }

    if len(links) > 0 {
        internal := false
        url := ""

        for !internal {
            attributes, err := dom.GetAttributes(links[rand.Intn(len(links))])
            if err != nil { log.Fatalf("Error getting attributes: %s\n", err) }

            attributesMap := make(map[string]string)
            for i := 0; i < len(attributes); i += 2 {
                attributesMap[attributes[i]] = attributes[i+1]
            }

            if _, hasHref := attributesMap["href"]; !hasHref { continue }

            url = attributesMap["href"]

            // TODO: Verify rules determining if link is internal
            if url != "" && (strings.HasPrefix(url, "https://" + overt) || strings.HasPrefix(url, "//" + overt) || !strings.Contains(url, "://")) {
                if !strings.Contains(url, "://") {
                    // TODO: Fix trimming when path has no slash
                    if strings.HasPrefix(url, "/") { url = "https://" + overt + url } else { url = strings.TrimRightFunc(current_url, func(r rune) bool { return r != '/' }) + url }
                }

                // TODO: Can be less restrictive, while ensuring a fresh page load
                if url != current_url && !strings.Contains(url, "#") && !strings.Contains(url, "?") { internal = true }
            }
        }

        // TODO: Handle broken links
        current_url = url
        log.Printf("Following link to %s\n", current_url)

        _, _, err = target.Page.Navigate(current_url, "", "")
        if err != nil { log.Fatalf("Error navigating to %s: %s\n", current_url, err) }
    } else {
        // Improve error handling and possibly try returning to previous page
        log.Fatalf("Ran out of links\n")
    }
}

func requestIntercepted(target *gcd.ChromeTarget, event []byte) {
    var err error

    eventUnmarshal := &gcdapi.NetworkRequestInterceptedEvent{}
    err = json.Unmarshal(event, eventUnmarshal)
    if err != nil { log.Fatalf("Error unmarshalling request: %s\n", err) }

    log.Printf("Intercepted request to %s\n", eventUnmarshal.Params.Request.Url)

    request, err := http.NewRequest(eventUnmarshal.Params.Request.Method, eventUnmarshal.Params.Request.Url, strings.NewReader(eventUnmarshal.Params.Request.PostData))
    if err != nil { log.Fatal("Error creating request: %s\n", err) }

    for k, v := range eventUnmarshal.Params.Request.Headers {
        request.Header.Add(k, v.(string))
    }

    var response *http.Response

    // TODO: Investigate failed binary file fetches
    for {
        response, err = client.Do(request)
        if err != nil { log.Printf("Failed to fetch %s, retrying... (%s)\n", eventUnmarshal.Params.Request.Url, err) } else { break }
    }

    defer response.Body.Close()
    body, err := ioutil.ReadAll(response.Body)
    if err != nil { log.Fatalf("Error reading body: %s\n", err) }

    var headers bytes.Buffer
    err = response.Header.Write(&headers)
    if err != nil { log.Fatalf("Error reading header: %s\n", err) }

    reply := fmt.Sprintf("%s %s\r\n%s\r\n\r\n%s", response.Proto, response.Status, headers, body)

    _, err = target.Network.ContinueInterceptedRequest(eventUnmarshal.Params.InterceptionId, "", base64.StdEncoding.EncodeToString([]byte(reply)), "", "", "", map[string]interface{}{}, nil)
    if err != nil { log.Fatalf("Error replying to intercept: %s\n", err) }
}
