/*
Copyright © 2022 ALASTOR INFOSEC <security@alastorinfosec.com>
*/
package cmd

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"

	"github.com/spf13/cobra"
)

// inactiveCmd represents the inactive command
var inactiveCmd = &cobra.Command{
	Use:   "inactive",
	Short: "Convert Inactive Subdomain File",
	Run: func(cmd *cobra.Command, args []string) {
		// get flag value
		inactiveInput, _ := cmd.Flags().GetString("input")
		inactiveOutput, _ := cmd.Flags().GetString("output")
		// validate if flags are provided
		if inactiveInput != "" && inactiveOutput != "" {
			readinactive(inactiveInput, inactiveOutput)
		} else if inactiveInput != "" && inactiveOutput == "" {
			fmt.Print("Missing Flag: Use --output <output-file.csv>\n")
		} else if inactiveInput == "" && inactiveOutput != "" {
			fmt.Print("Missing Flag: Use --input <input-file.txt>\n")
		} else {
			cmd.Help()
		}
	},
}

func init() {
	rootCmd.AddCommand(inactiveCmd) // add this command to root command
	// define flags
	inactiveCmd.PersistentFlags().String("input", "", "Input File Location")
	inactiveCmd.PersistentFlags().String("output", "", "Output File Location")
}

func readinactive(inactiveInput, inactiveOutput string) {
	log.SetFlags(log.LstdFlags | log.Lshortfile) // get log location
	// open file
	f, err := os.Open(inactiveInput)
	// check for errors
	if err != nil {
		log.Fatal(err)
	}
	// remember to close the file at the end of the program
	defer f.Close()
	// read the file line by line using scanner
	scanner := bufio.NewScanner(f) //By default only handle 4MB of input
	//Increase limit to handle input file upto 100 MB
	const maxCapacity = 104857600
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	// Create csv file
	OutputReportFile := path.Join(inactiveOutput)
	csvfile, err := os.OpenFile(OutputReportFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	// check for errors
	if err != nil {
		log.Fatal(err)
		return
	}
	defer csvfile.Close() // remeber to close file once done

	writer := csv.NewWriter(csvfile)
	defer writer.Flush()
	// matching regex
	ipv6_regex := `^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$`
	ipv4_regex := `^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.|$)){4})`
	domain_regex := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$`

	// create loop to match line by line
	for scanner.Scan() {
		var data []string
		// match regex with file content
		domainmatch, _ := regexp.MatchString(domain_regex, scanner.Text())
		ipv4match, _ := regexp.MatchString(ipv4_regex, scanner.Text())
		ipv6match, _ := regexp.MatchString(ipv6_regex, scanner.Text())
		// check which conditions matches
		if domainmatch {
			data = append([]string{scanner.Text()}, "subdomain")
		} else if ipv4match {
			data = append([]string{scanner.Text()}, "IPv4 Address")
		} else if ipv6match {
			data = append([]string{scanner.Text()}, "IPv6 Address")
		} else if err != nil {
			log.Fatal(err)
		} else {
			data = append([]string{scanner.Text()}, "Uncategorized")
		}
		// dumping data to csv
		writer.Write(data)
	}
	// check for errors
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}
