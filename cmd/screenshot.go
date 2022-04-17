/*
Copyright © 2022 ALASTOR INFOSEC <security@alastorinfosec.com>

*/
package cmd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/spf13/cobra"
)

// screenshotCmd represents the screenshot command
var screenshotCmd = &cobra.Command{
	Use:     "screenshot",
	Short:   "Use to create JSON file with Screenshot Data",
	Example: `goasseter screenshot --input httpx.json --output screenshots.json`,
	Run: func(cmd *cobra.Command, args []string) {
		// gets flag value
		activeInput, _ := cmd.Flags().GetString("input")
		activeOutput, _ := cmd.Flags().GetString("output")
		delay, _ := cmd.Flags().GetInt("delay")
		// validate if flags are provided
		if activeInput != "" && activeOutput != "" {
			removeFile(activeOutput)
			createJSON(activeInput, activeOutput, delay)
		} else if activeInput != "" && activeOutput == "" {
			fmt.Print("Missing Flag: Use --output <output-file.json>\n")
		} else if activeInput == "" && activeOutput != "" {
			fmt.Print("Missing Flag: Use --input <input-file.json>\n")
		} else {
			cmd.Help()
		}
	},
}

func init() {
	// define flags
	screenshotCmd.PersistentFlags().String("input", "", "(httpx.json) HTTPx JSON File Location")
	screenshotCmd.PersistentFlags().String("output", "", "(screenshots.json) Output JSON File Location")
	screenshotCmd.PersistentFlags().Int("delay", 5, "Number of second to dalay the screenshot capture to let CSS animations load")
	rootCmd.AddCommand(screenshotCmd) // adds to root command
}

type NewData struct {
	Url          string `json:"url"`
	Title        string `json:"title"`
	Technologies string `json:"tech"`
	Length       string `json:"length"`
	Headers      string `json:"headers"`
	Imgdata      string `json:"imgdata"`
}

func screenshotTasks(url string, imageBuf *[]byte, delay int) chromedp.Tasks { // use chromdp package to take screenshot
	log.SetFlags(log.LstdFlags | log.Lshortfile) // gets error line
	return chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.Sleep(time.Duration(delay) * time.Second), // wait for 5 second before taking screenshot (to let animation loads)
		chromedp.ActionFunc(func(abc context.Context) (err error) {
			*imageBuf, err = page.CaptureScreenshot().Do(abc) // take screenshot in png and store in buffer
			return err
		}),
	}
}

func headersTasks(url string, delay int) string { //get http resp headers using http/net package
	log.SetFlags(log.LstdFlags | log.Lshortfile) // gets error line

	// client := http.Client{
	// 	Timeout: time.Duration(delay) * time.Second,
	// 	CheckRedirect: func(req *http.Request, via []*http.Request) error {
	// 		return http.ErrUseLastResponse
	// 	},
	// }
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //ignore bad ssl certification

	// resp, err := client.Get(url) //make http req
	// if err != nil {
	// 	log.Println(nil, err)
	// }
	// defer resp.Body.Close() //close once done

	resp, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}
	resp.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_4) AppleWebKit/600.7.12 (KHTML, like Gecko) Version/8.0.7 Safari/600.7.12")
	// defer resp.Body.Close() //close once done

	repRes := new(bytes.Buffer) //create emptybuffer
	// fmt.Println(url, resp.StatusCode)
	for key, value := range resp.Header { //store http headers into buffer
		fmt.Fprintf(repRes, ">>>  %s : %s\n", key, value)
	}
	return repRes.String() //return buffer as strings
}

func createJSON(inputFile, outFile string, delay int) {
	log.SetFlags(log.LstdFlags | log.Lshortfile) // gets error line
	//open input file
	jsonFile, err := os.Open(inputFile) //open input file
	if err != nil {
		log.Println("[!] Failed to Open Input File:", err)
	}
	//read data
	jsonData := bufio.NewScanner(jsonFile) // by default handles 4MB data only
	//To handle upto 100 MB data
	const maxCapacity = 104857600
	buf := make([]byte, maxCapacity)
	jsonData.Buffer(buf, maxCapacity)

	data := Data{}
	// read json object line by line
	for jsonData.Scan() {
		// marshal json data & check for logs
		if err := json.Unmarshal(jsonData.Bytes(), &data); err != nil {
			log.Println("[!] Failed to marhsal JSON data:", err)
		}
		// store date at once
		abc, cancel := chromedp.NewContext(context.Background())
		defer cancel()

		var imageBuf []byte //create byte array to store image data

		chromedp.Run(abc, screenshotTasks(data.Url, &imageBuf, delay))
		if err != nil {
			fmt.Println("[!] Failed to take screenshot of: ", data.Url)
		}
		repRes := headersTasks(data.Url, delay) //run headers function to get headers

		var base64Encoding string
		base64Encoding += "data:image/png;base64,"
		base64Encoding += base64.StdEncoding.EncodeToString(imageBuf)

		//prepares json output
		newdata := NewData{
			Url:          data.Url,
			Title:        data.Title,
			Technologies: strings.Join(data.Technologies, ","),
			Length:       string(data.Length),
			Headers:      repRes,
			Imgdata:      base64Encoding,
		}
		//save to json
		file, _ := json.Marshal(newdata)
		if data.StatusCode == "400" {
			fmt.Println("[!] Server returns 400 Status Code. Skipping:", data.Url)
		} else if data.Host == "127.0.0.1" {
			fmt.Println("[!] Server redicting to 127.0.0.1. Skipping:", data.Url)
		} else {
			fmt.Println("[+] Screenshot completed for:", data.Url)
			write2file(outFile, file)
		}
	}
	// check for logs
	if jsonData.Err() != nil {
		log.Fatal(err)
	}
}

func removeFile(outFile string) {
	os.Remove(outFile)
}

func write2file(outFile string, file []byte) {
	f, err := os.OpenFile(outFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()
	if _, err = f.WriteString(string(file)); err != nil {
		log.Fatal(err)
	}
	if _, err = f.WriteString("\n"); err != nil {
		log.Fatal(err)
	}
}
