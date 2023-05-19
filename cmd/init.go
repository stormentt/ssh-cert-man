/*
Copyright © 2023 Tanner Storment

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/
package cmd

import (
	"fmt"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stormentt/ssh-cert-man/certs"
	"golang.org/x/term"
)

// initCmd represents the init command
var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create the SSH certificate authority",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		caPath := viper.GetString("ca.path")
		fmt.Printf("Enter Password: ")
		pwBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			panic(err)
		}

		err = certs.GenerateCA(caPath, pwBytes)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(initCmd)

	viper.SetDefault("ca.path", "ca_ed25519.json")
}
