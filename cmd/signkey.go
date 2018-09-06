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

	"golang.org/x/crypto/openpgp"

	"github.com/spf13/cobra"
	"github.com/thalesignite/crypto11"
)

var keyPath string

// signkeyCmd represents the signkey command
var signkeyCmd = &cobra.Command{
	Use:   "signkey",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("signkey called")
		// _, err := os.Open(keyPath)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// newEntity, _ := util.NewEntityFromRSABits(
		// 	"test",
		// 	"test-comment",
		// 	"test@example.com",
		// 	nil)

		ctx, err := crypto11.ConfigureFromFile("./softhsm2config.json")
		if err != nil {
			log.Fatal(err)
		}
		var pkey openpgp.Identity

		pkey.
			fmt.Println(ctx)
		// sh, err := ctx.OpenSession(0, 0)
		ms, err := ctx.GetMechanismList(1)
		fmt.Println(ctx.GetMechanismInfo(1, ms))

		// ctx.GenerateKeyPair(sh)
		panic("die")

		// outFile, err := armor.Encode(os.Stdout, "PGP PUBLIC KEY BLOCK", map[string]string{"Version": "GnuPG v1"})
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// newEntity.Serialize(outFile)
		// outFile.Close()
	},
}

func init() {
	rootCmd.AddCommand(signkeyCmd)
	verifyCmd.Flags().StringVar(&keyPath, "key", "", "Path to private key")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// signkeyCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// signkeyCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
