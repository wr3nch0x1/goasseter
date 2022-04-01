/*
Copyright © 2022 ALASTOR INFOSEC <security@alastorinfosec.com>

*/
package cmd

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"
)

// activeCmd represents the active command
var activeCmd = &cobra.Command{
	Use:   "active",
	Short: "Create Active Assset CSV from httpx JSON",
	Run: func(cmd *cobra.Command, args []string) {
		// gets flag value
		activeInput, _ := cmd.Flags().GetString("input")
		activeOutput, _ := cmd.Flags().GetString("output")
		// validate if flags are provided
		if activeInput != "" && activeOutput != "" {
			readactive(activeInput, activeOutput)
		} else if activeInput != "" && activeOutput == "" {
			fmt.Print("Missing Flag: Use --output <output-file.csv>\n")
		} else if activeInput == "" && activeOutput != "" {
			fmt.Print("Missing Flag: Use --input <input-file.json>\n")
		} else {
			cmd.Help()
		}
	},
}

func init() {
	// define flags
	activeCmd.PersistentFlags().String("input", "", "Input File Location")
	activeCmd.PersistentFlags().String("output", "", "Output CSV File Location")
	rootCmd.AddCommand(activeCmd) // adds to root command
}

// json object values to store data
type Data struct {
	Url          string   `json:"url"`
	Input        string   `json:"input"`
	Technologies []string `json:"technologies"`
	Port         string   `json:"port"`
	Scheme       string   `json:"scheme"`
	Title        string   `json:"title"`
}

func readactive(activeInput, activeOutput string) {
	log.SetFlags(log.LstdFlags | log.Lshortfile) // gets error line
	//open input file
	jsonFile, err := os.Open(activeInput)
	if err != nil {
		log.Fatal(err)
	}
	//read data
	jsonData := bufio.NewScanner(jsonFile) // by default handles 4MB data only
	//To handle upload 100 MB data
	const maxCapacity = 104857600
	buf := make([]byte, maxCapacity)
	jsonData.Buffer(buf, maxCapacity)

	// Save in csv
	OutputReportFile := path.Join(activeOutput)
	csvfile, err := os.OpenFile(OutputReportFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	// check for errors
	if err != nil {
		log.Fatal(err)
		return
	}
	defer csvfile.Close() // remember to close file

	writer := csv.NewWriter(csvfile)
	defer writer.Flush()

	data := Data{}
	// read json object line by line
	for jsonData.Scan() {
		// marshal json data & check for logs
		if err := json.Unmarshal(jsonData.Bytes(), &data); err != nil {
			log.Fatal(err)
		}
		// store date at once
		records := [][]string{{data.Input, "subdomain", (strings.Join(data.Technologies, "-")), data.Port, data.Scheme, data.Title}}
		// dump data to csv
		for _, record := range records {
			err := writer.Write(record)
			// check for logs
			if err != nil {
				log.Fatal(err)
				return
			}
		}
		// check for logs
		if jsonData.Err() != nil {
			log.Fatal(err)
		}
	}
}
