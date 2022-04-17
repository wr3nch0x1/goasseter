/*
Copyright © 2022 ALASTOR INFOSEC <security@alastorinfosec.com>

*/
package cmd

import (
	"bufio"
	"fmt"
	"os/exec"

	"github.com/spf13/cobra"
)

// onegoCmd represents the onego command
var onegoCmd = &cobra.Command{
	Use:     "onego",
	Short:   "Run all three commands (Activ/Inactive/Screenshot) in just 1 go",
	Example: `goasseter onego --input inactive.txt`,
	Run: func(cmd *cobra.Command, args []string) {
		inactiveInput, _ := cmd.Flags().GetString("input")
		if inactiveInput != "" {
			removeFile("onego_inactive_output.csv")
			removeFile("onego_screenshots_output.json")
			removeFile("onego_active_output.csv")
			removeFile("onego_httpx.json")
			fmt.Println("[+] Preparing Active Assets CSV output")
			readinactive(inactiveInput, "onego_inactive_output.csv")
			RunHTTPx(inactiveInput)
			readactive("onego_httpx.json", "onego_active_output.csv")
			createJSON("onego_httpx.json", "onego_screenshots_output.json", 3)
			removeFile("onego_ipmap.json")
			readIPfromJSON("onego_httpx.json", "onego_ipmap.json", 3)
			fmt.Println("Execution Completed!")
		} else {
			fmt.Println("\n[-] Please specify input file")
			cmd.Help()
		}
	},
}

func init() {
	onegoCmd.PersistentFlags().String("input", "", "Resolved Host txt List")
	rootCmd.AddCommand(onegoCmd)
}

func RunHTTPx(inactiveInput string) {

	execname := "httpx"

	cmd := exec.Command(execname, "-l", inactiveInput, "-silent", "-json", "-stats", "-td", "-title", "-server", "-fr", "-random-agent", "-ports", "80,443,8080,8000,8443,8888,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672", "-o", "onego_httpx.json")
	fmt.Println("[+] Running HTTPx and waiting for it to finish...")

	// var out bytes.Buffer
	// var stderr bytes.Buffer
	// cmd.Stdout = &out
	// cmd.Stderr = &stderr
	// err := cmd.Start()
	// if err != nil {
	// 	fmt.Println(fmt.Sprint(err) + ": " + stderr.String())
	// 	return
	// }
	// fmt.Println(out.String()) //this is to show output for debugging

	stderr, _ := cmd.StderrPipe()
	cmd.Start()

	scanner := bufio.NewScanner(stderr)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		m := scanner.Text()
		fmt.Println(m)
	}
	cmd.Wait()
	fmt.Println("[+] HTTPx Completed and Output stored in: onego_httpx.json")
}
