// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/openpgp"
)

var pubKeyPath string
var sigPath string
var inputFilePath string

// verifyCmd represents the verify command
var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify signature matches file and was created by public-key.",
	Long: `Verify signature matches file and was created by public-key \
by doing the following, in order:

1. Read public-key and check that it is valid, else exit 1
2. Check signature against public-key, else exit 3
3. Create digest of file
4. Compare digest to that in signature, else exit 5
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("verify called")
		pubKeyFile, err := os.Open(pubKeyPath)
		if err != nil {
			log.Fatal(err)
		}
		keyring, err := openpgp.ReadArmoredKeyRing(pubKeyFile)
		if err != nil {
			log.Fatal(err)
		}
		signature, err := os.Open(sigPath)
		if err != nil {
			log.Fatal(err)
		}
		inputFile, err := os.Open(inputFilePath)
		if err != nil {
			log.Fatal(err)
		}
		entity, err := openpgp.CheckDetachedSignature(keyring, inputFile, signature)
		if err != nil {
			fmt.Println("Check Detached Signature: " + err.Error())
			return
		}

		fmt.Print(entity.Identities)
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringVar(&pubKeyPath, "pubkey", "", "Path to public key")
	verifyCmd.Flags().StringVar(&sigPath, "sig", "", "Path to file signature")
	verifyCmd.Flags().StringVar(&inputFilePath, "input", "", "Path to input file to be verified")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// verifyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// verifyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
