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

	"github.com/spf13/cobra"
	"github.com/stormentt/ssh-cert-man/certs"
	"golang.org/x/crypto/ssh"
)

// printCaCmd represents the printCa command
var printCaCmd = &cobra.Command{
	Use:   "printCa",
	Short: "Prints the CA public key",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		castore, err := certs.LoadCA()
		if err != nil {
			panic(err)
		}

		pubkey, err := ssh.NewPublicKey(castore.Pub)

		marshalled := ssh.MarshalAuthorizedKey(pubkey)
		fmt.Printf("%s", marshalled)
	},
}

func init() {
	rootCmd.AddCommand(printCaCmd)
}
