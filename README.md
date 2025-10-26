# Telegram Forward Bot

This project provides a Telegram forwarder built with [Telethon](https://docs.telethon.dev/).
It authenticates as a full user account (so the userbot can join and read source
channels) but exposes a configuration interface through a dedicated Bot API
controller. Use the bot to create forwarding rules and the signed-in user
account will relay matching messages in real time.

## Requirements

* **Python** 3.8 or newer. The script uses modern asyncio features that require at least Python 3.8.
* **Dependencies**: install with `pip install telethon python-dotenv`.
* **Telegram API credentials**: create an app at [https://my.telegram.org](https://my.telegram.org) to obtain:
  * `TELETHON_API_ID`
  * `TELETHON_API_HASH`
* **Session name (optional)**: set `TELETHON_SESSION` to change the filename used to store the user login session (defaults to `userbot_forwarder`).
* **Phone number for first-run login**: set `TELETHON_PHONE_NUMBER` so the script can request an authorization code directly from Telegram when no session exists. Once a session is saved you can remove this value.
* **Bot token**: set `TELEGRAM_BOT_COOKIE` to the token provided by [@BotFather](https://t.me/BotFather). The script will log in as this bot to receive setup commands.
* **Authorized controllers**: set `TELEGRAM_OWNER_IDS` to a comma-separated list of Telegram user IDs. Only these users can issue commands to the controller bot.

## Setup

1. Join both the source and destination chats with the user account that will run the forwarder.
2. Create a Telegram bot and copy its token.
3. Create a `.env` file in the project directory with the required environment variables:
   ```env
   TELETHON_API_ID=123456
   TELETHON_API_HASH=your_api_hash
   TELEGRAM_BOT_COOKIE=123456:ABC-DEF1234   # Bot token from BotFather
   TELEGRAM_OWNER_IDS=111111111,222222222   # Controller Telegram user IDs
   TELETHON_SESSION=userbot_forwarder       # Optional custom session name
   TELETHON_PHONE_NUMBER=+15551234567       # Phone number for first-run login
   ```
4. Run the forwarder with `python bot.py`. On the first launch the script sends a message through the controller bot asking authorized owners to provide the login code with `/code 12345` (and `/password your_password` if two-factor authentication is enabled). Subsequent runs reuse the saved session. The script automatically loads variables from the `.env` file using `python-dotenv`.
5. Open a private chat with the controller bot using one of the authorized accounts:
   * Send `/listchats` to receive a list of chats and channels the user account can access along with their numeric IDs.
   * Send `/forward` and follow the prompts:
     1. Provide the numeric source chat ID.
     2. Provide the numeric destination chat ID.
     3. Choose whether to forward `all` messages or only `media` (photos and videos).
6. Repeat `/forward` for additional rules. Rules persist until you stop the process.

## Forwarding modes

During `/forward` setup you choose between:

* `all` – forward every message from the source chat.
* `media` – forward only photos and videos.

The chosen rules remain in memory until you stop the process. Restarting the script requires reconfiguring the rules.

## Troubleshooting

* **`TELETHON_API_ID and TELETHON_API_HASH must be set.`** – make sure both environment variables are exported before running `python bot.py`.
* **`TELEGRAM_OWNER_IDS must provide at least one user ID when TELEGRAM_BOT_COOKIE is set.`** – bot mode requires a list of authorized controllers.
* **Login pending** – respond to the controller bot with `/code <digits>` after Telegram delivers the code to your account. If the account has two-factor authentication enabled, follow up with `/password <your_password>`.
* **Entity resolution failures** – ensure the user account has joined the source and destination chats and that you provide valid numeric IDs when prompted.

