package mobyconfig

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
)

type myjar struct {
	jar map[string][]*http.Cookie
}

func (p *myjar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	p.jar[u.Host] = cookies
}

func (p *myjar) Cookies(u *url.URL) []*http.Cookie {
	return p.jar[u.Host]
}

type hubServer struct {
	client *http.Client
	Config *Config
}



func (h *hubServer) login() bool {
	// check if the Config entry is initialized
	if h.Config == nil {
		fmt.Printf("ERROR in HubServer no configuration available.\n")
		return false
	}

	fmt.Println(h.Config.Url)
	u, err := url.ParseRequestURI(h.Config.Url)
	if err != nil {
		fmt.Printf("ERROR : url.ParseRequestURI\n%s\n", err)
		return false
	}

	resource := "/j_spring_security_check"
	u.Path = resource
	data := url.Values{}
	data.Add("j_username", h.Config.User)
	data.Add("j_password", h.Config.Password)

	h.client = &http.Client{}

	jar := &myjar{}
	jar.jar = make(map[string][]*http.Cookie)
	h.client.Jar = jar

	urlStr := fmt.Sprintf("%v", u)
	req, err := http.NewRequest("POST", urlStr, bytes.NewBufferString(data.Encode()))
	if err != nil {
		fmt.Printf("ERROR NewRequest:\n%s\n", err)
		return false
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded") // needed this the prevend 401 Unauthorized

	resp, err := h.client.Do(req)
	if err != nil {
		fmt.Printf("ERROR client.do\n%s\n", err)
		return false
	}
	resp.Body.Close()
	if resp.StatusCode != 204 {
		fmt.Printf("ERROR : resp status : %s\n%d\n", resp.Status, resp.StatusCode)
		return false
	}
	return true
}


