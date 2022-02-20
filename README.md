# This script assists to check resources on the particular client

## Function

The script gathers domains where it will send attacks to. Supported schemes: http, https, ws, wss
The domains may be defined either in local txt file `client_domains` or in [GSheets](https://docs.google.com/spreadsheets/d/XXX/edit?usp=sharing).
It if feasible to use either Apps bound to your account or, as in this case, Service Account which shares access only to the permitted sheets. This account exists in the `client-monitoring-services` project in Google APIs. Then the script attacks domains, wait a minute and addresses to Wallarm API to find out if everything was detected, and if not it sends a notification of what domain has not appeared in Wallarm cloud, otherwise, it sends a message that everything's going well.

## Usage

* Create an `env.conf` where UUID and SECRET are for `partner_auditor` account on the same partner as the target client

```sh
WALLARM_API_HOST=api.wallarm.com
WALLARM_UUID=00000000-0000-0000-0000-000000000000
WALLARM_SECRET=00000000000000000000000000000000000000000000000000000000
TELEGRAM_TOKEN=000000000:000000000000000000000-0000000000000
CHAT_ID=000000000
```
1. Local file configuration
  * Create a list of target domains `client_domains` similar to the example below

    ```sh
    http://example.com
    https://example.com
    wss://www.example.com/socketserver
    ```

  * Create a cron job in `/etc/cron.d/client` with the following content

    ```sh
    0  */5  * * *   root docker rm -v $(docker ps -a -q -f "label=wlrm=check") || true && docker run -d --name wlrm --restart on-failure -v /home/debian/client_domains:/wlrm-check-resources/domains --env-file=/home/debian/env.conf awallarm/wlrm-check
    ```
2. Google Sheets configuration
  * Use the [Sheet](https://docs.google.com/spreadsheets/d/XXX/edit?usp=sharing) where domains are defined

  * `jwt-credentials.json` are credentials for your Google Service Account

  * Create a cron job in `/etc/cron.d/client` with the following content

    ```sh
    0  */5  * * *   root docker rm -v $(docker ps -a -q -f "label=wlrm=check") || true && docker run -d --name wlrm --restart on-failure -v /home/debian/jwt-credentials.json:/wlrm-check-resources/ --env-file=/home/debian/env.conf awallarm/wlrm-check
    ```

## Disable domain from scan

You may exclude a domain by removing it from the list, that being said, you may want to keep it thereafter, so comment it with a hashtag `#` in the very beginning on the line
```sh
http://example.com
https://example.com
#ws://www.example.com/
#wss://www.example.com/
```