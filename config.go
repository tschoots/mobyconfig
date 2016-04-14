package mobyconfig

import (
	"archive/zip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"path/filepath"
)



var key = []byte("pronktjiesparktr535afasdf asdnvr")

type config struct {
	Url      string `json:"url"`
	Host     string `json:"hubhost"`
	Port     string `json:"port"`
	Scheme   string `json:"scheme"`
	User     string `json:"user"`
	Password string `json:"password"`
	MaxScans int `json:"maxscans"`
	MaxUploadSize int `json:"maxuploadsize"` 
}

func  GetConfig(configJsonFile string) (*config, bool) {
	// check if the json file in conf/config.json exist
	if _, err := os.Stat(configFile); err != nil {
		if os.IsNotExist(err) {
			return nil, false
		} else {
			fmt.Errorf("file %s has problems : \n%s\n", config_file, err)
			return nil, false
		}

	} else {
		// config_file exists read it and unmarshall
		conf := &config{}
		
		file, err := ioutil.ReadFile(config_file)
		if err != nil {
			fmt.Errorf("ERROR readfile %s : \n%s\n", config_file, err)
			return nil, false
		}
		
		json.Unmarshal(file, conf)
		conf.Password = decrypt(key, conf.Password)
		return conf, true

	}

}

func CreateConfig(configJsonFile string) (*config , bool) {
	conf := config{ConfigFile: configJsonFile}
	
	conf.init()
	
	jsonString , err := json.Marshal(conf)
	if err != nil {
		fmt.Errorf("Error marshall configuration: %s\n\n", err)
		return nil, false
	}
	
	if err := os.MkdirAll(filepath.Dir(config_file), 0755); err != nil {
		fmt.Errorf("Error creating directory %s : \n%s\n\n", filepath.Dir(config_file), err)
		return nil, false
	}
	
	if err := ioutil.WriteFile(config_file, jsonString, 0755); err != nil {
		fmt.Errorf("error writing config file : %s\n\n", err)
		return nil, false
	}
	
	conf.Password = decrypt(key, conf.Password)
	
	if err := os.MkdirAll(cli_path, 0755); err != nil {
		fmt.Errorf("Error creating directory %s: \n%s\n\n", cli_path, err)
		return nil, false
	}
	
	downloadUrl := fmt.Sprintf("%s/%s", conf.Url, cli_url)
	downloadFromUrl(downloadUrl)
	return &conf, true
}

func (c *config) init() {

	// config file doesn't exist so get data from the user
	var hubUrl string
	
	fmt.Println("Max number of scans : ")
	fmt.Scanln(&c.MaxScans)
	
	fmt.Println("Max upload size in mb : ")
	fmt.Scanln(&c.MaxUploadSize)

	fmt.Println("Enter url formate http|https://<server>[:port]: ")
	fmt.Scanln(&hubUrl)

	fmt.Printf("hub user: \n")
	fmt.Scanln(&c.User)

	fmt.Printf("password:")
	fmt.Println("\033[8m")
	fmt.Scanln(&c.Password)
	fmt.Println("\033[28m")

	u, err := url.Parse(hubUrl)
	if err != nil {
		panic(err)
	}

	c.Url = fmt.Sprintf("%s://%s", u.Scheme, u.Host)

	c.Scheme = u.Scheme

	if strings.Compare(c.Scheme, "https") == 0 {
		c.Port = "443"
	} else {
		c.Port = "80"
	}
	c.Host = u.Host
	if strings.Contains(c.Host, ":") {
		host, port, _ := net.SplitHostPort(c.Host)
		c.Host = host
		c.Port = port
	}

	if valid := c.validUseridPassword(); !valid {
		fmt.Printf("ERROR user id password combination not valid.")
		os.Exit(2)
	}
	c.Password = encrypt(key, c.Password)

}

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

func (c *config) validUseridPassword() bool {

	hubServer := HubServer{Config: c}
	
	return hubServer.login()
}




