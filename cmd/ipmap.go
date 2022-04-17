/*
Copyright © 2022 ALASTOR INFOSEC <security@alastorinfosec.com>
*/
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
)

type jsonOut struct {
	Ip  string `json:"ip"`
	Loc string `json:"loc"`
}

type jsonIn struct {
	Host string `json:"host"`
}

// ipmapCmd represents the ipmap command
var ipmapCmd = &cobra.Command{
	Use:   "ipmap",
	Short: "Create JSON file using IPinfo.io for IP location",
	Long:  `goasseter ipmap --input httpx.json --output ipmap.json`,
	Run: func(cmd *cobra.Command, args []string) {
		// gets flag value
		activeInput, _ := cmd.Flags().GetString("input")
		activeOutput, _ := cmd.Flags().GetString("output")
		timeout, _ := cmd.Flags().GetInt("timeout")
		// validate if flags are provided
		if activeInput != "" && activeOutput != "" {
			removeFile(activeOutput)
			readIPfromJSON(activeInput, activeOutput, timeout)
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
	ipmapCmd.PersistentFlags().String("input", "", "(httpx.json) HTTPx JSON File Location")
	ipmapCmd.PersistentFlags().String("output", "", "(ipmap.json) Output JSON File Location")
	ipmapCmd.PersistentFlags().Int("timeout", 5, "Request Timeout for HTTP Request")
	rootCmd.AddCommand(ipmapCmd)
}

func GetGeoIP(url string, outFile string, timeout int) {
	log.SetFlags(log.LstdFlags | log.Lshortfile) // gets error line

	geoClient := http.Client{
		Timeout: time.Second * time.Duration(timeout), // Timeout after 5 seconds
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	req.Header.Set("accept", "application/json")

	res, getErr := geoClient.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	jsonout := jsonOut{}
	jsonErr := json.Unmarshal(body, &jsonout)
	if jsonErr != nil {
		log.Fatal(jsonErr)
	}
	file, _ := json.Marshal(jsonout)
	write2file(outFile, file)
	// fmt.Println(jsonout)
}

func readIPfromJSON(filename string, outFile string, timeout int) {
	data := jsonIn{}
	//open input file
	jsonFile, err := os.Open(filename) //open input file
	if err != nil {
		log.Fatal(err)
	}
	defer jsonFile.Close()
	//read data
	jsonData := bufio.NewScanner(jsonFile) // by default handles 4MB data only
	//To handle upto 100 MB data
	const maxCapacity = 104857600
	buf := make([]byte, maxCapacity)
	jsonData.Buffer(buf, maxCapacity)

	for jsonData.Scan() {

		// marshal json data & check for logs
		if err := json.Unmarshal(jsonData.Bytes(), &data); err != nil {
			log.Fatal(err)
		}
		//save to file
		url := fmt.Sprintf("http://ipinfo.io/%s", data.Host)
		GetGeoIP(url, outFile, timeout)

	}
}
