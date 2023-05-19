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
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

var principals []string
var extensions []string
var certType string
var certID string

// signCmd represents the sign command
var signCmd = &cobra.Command{
	Use:   "sign [public key] [certificate]",
	Short: "Signs a certificate using our CA",
	Long:  ``,
	Args:  cobra.MatchAll(cobra.ExactArgs(2)),
	Run: func(cmd *cobra.Command, args []string) {
		caPath := viper.GetString("ca.path")
		fmt.Printf("Enter Password: ")
		pwBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			panic(err)
		}

		castore, err := certs.LoadCA(caPath, pwBytes)

		var realCertType uint32
		switch certType {
		case "host":
			realCertType = ssh.HostCert
		case "user":
			realCertType = ssh.UserCert
		default:
			panic("invalid cert type specified")
		}

		err = castore.Sign(args[1], args[0], realCertType, principals, extensions, certID)
		if err != nil {
			panic(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(signCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// signCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	signCmd.Flags().StringVarP(&certType, "type", "t", "user", "type of cert: [user,host]")
	signCmd.Flags().StringVarP(&certID, "id", "i", "", "Cert ID")
	signCmd.Flags().StringSliceVarP(&principals, "principals", "p", []string{}, "User or host names to be included in the certificate")
	signCmd.Flags().StringSliceVarP(&extensions, "extensions", "e", []string{}, "SSH Certificate Extensions")

	signCmd.MarkFlagRequired("principals")
}
