// +build linux darwin

package main

import (
	"os"
	"wlrm-check-resources/wapi"

	"github.com/urfave/cli"
)

func main() {

	app := cli.NewApp()
	app.Usage = "Test application with Wallarm."
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "method, m",
			Usage: "Request method to be used",
			Value: "GET",
		},
		cli.IntFlag{
			Name:  "clientID, c",
			Usage: "Client ID of the account to be used",
			Value: 7,
		},
		cli.IntFlag{
			Name:  "duration, d",
			Usage: "Sleep duration in seconds (wait while attacks are exporting)",
			Value: 60,
		},
	}
	app.Commands = []cli.Command{
		{
			Name:  "file",
			Usage: "When a local file is used",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "path, p",
					Usage: "Path to the local file",
					Value: "/etc/wlrm/domains.conf",
				},
			},
			Action: func(c *cli.Context) error {
				method = c.GlobalString("method")
				clientID = c.GlobalInt("clientID")
				duration = c.GlobalInt("duration")
				ctx, env := checkEnv()
				client := wapi.NewClient(env.uuid, env.secret, env.telegramToken, env.chatID)
				client.SourceMeans = "file"
				client.FilePath = c.String("path")
				run(ctx, client)
				return nil
			},
		},
		{
			Name:  "gdocs",
			Usage: "When Google docs is used",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "id, i",
					Usage: "Sheets ID of the domains",
					Value: "1nPpcE_6kc1NHYfQZLrq7gjGO9-_TD-ZA4GXe1W9i1kE",
				},
				cli.StringFlag{
					Name:  "range, r",
					Usage: "Sheets Range where domains are defined",
					Value: "Domains!A2:1000",
				},
				cli.StringFlag{
					Name:  "jwt, j",
					Usage: "JWT Credentials for the Service Account which has permissions to read the Sheet",
				},
				cli.StringFlag{
					Name:  "appCreds, a",
					Usage: "App Credentials for the Service App which has permissions to read the Sheet",
				},
				cli.StringFlag{
					Name:  "token, t",
					Usage: "Token for the App Credentials",
				},
			},
			Action: func(c *cli.Context) error {
				method = c.GlobalString("method")
				clientID = c.GlobalInt("clientID")
				duration = c.GlobalInt("duration")
				ctx, env := checkEnv()
				client := wapi.NewClient(env.uuid, env.secret, env.telegramToken, env.chatID)
				client.SourceMeans = "gdocs"
				client.SheetsID = c.String("id")
				client.SheetsRange = c.String("range")
				client.JWTCreds = c.String("jwt")
				client.GDocsCreds = c.String("appCreds")
				client.GDocsToken = c.String("token")
				run(ctx, client)
				return nil
			},
		},
	}

	app.Run(os.Args)

}
