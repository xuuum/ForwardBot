diff --git a/README.md b/README.md
new file mode 100644
index 0000000000000000000000000000000000000000..fbf3b679ebf7c70b951cccb4d9c84b51f47f8c21
--- /dev/null
+++ b/README.md
@@ -0,0 +1,59 @@
+# Telegram Forward Bot
+
+This project provides a Telegram forwarder built with [Telethon](https://docs.telethon.dev/). It can sign in either as a full user account (userbot) or as a Bot API account and forward messages from one chat to another based on rules you configure over Telegram itself.
+
+## Requirements
+
+* **Python** 3.8 or newer. The script uses modern asyncio features that require at least Python 3.8.
+* **Dependencies**: install with `pip install telethon`.
+* **Telegram API credentials**: create an app at [https://my.telegram.org](https://my.telegram.org) to obtain:
+  * `TELETHON_API_ID`
+  * `TELETHON_API_HASH`
+* **Session name (optional)**: set `TELETHON_SESSION` to change the filename used to store the login session (defaults to `userbot_forwarder`).
+
+### Running as a userbot (recommended during development)
+
+1. Make sure the account you plan to use has joined both the source and destination chats.
+2. Export the required environment variables:
+   ```bash
+   export TELETHON_API_ID=123456
+   export TELETHON_API_HASH="your_api_hash"
+   # Optionally restrict who can configure forwarding rules
+   export TELEGRAM_OWNER_IDS="111111111,222222222"
+   ```
+3. Start the forwarder:
+   ```bash
+   python bot.py
+   ```
+4. When prompted, enter the login code that Telegram sends to your account. The session will be saved for future runs.
+5. Open any dialog with the account (for example Saved Messages) and send `/forward` to begin configuring rules.
+
+### Running as a bot (Bot API token)
+
+1. Create a bot via [@BotFather](https://t.me/BotFather) and copy the token (the "bot cookie").
+2. Gather the Telegram user IDs that are allowed to manage forwarding rules. You can obtain them by messaging [@userinfobot](https://t.me/userinfobot) or any other user ID bot.
+3. Export the environment variables:
+   ```bash
+   export TELETHON_API_ID=123456
+   export TELETHON_API_HASH="your_api_hash"
+   export TELEGRAM_BOT_COOKIE="123456:ABC-DEF1234"  # Bot token
+   export TELEGRAM_OWNER_IDS="111111111,222222222"   # Must be set in bot mode
+   ```
+4. Start the forwarder with `python bot.py`. The authorized IDs will receive a "Forwarder is online" message.
+5. From a 1:1 chat with the bot, send `/forward` and follow the prompts to configure a rule.
+
+## Forwarding modes
+
+During `/forward` setup you choose between:
+
+* `all` – forward every message from the source chat.
+* `media` – forward only photos and videos.
+
+The chosen rules remain in memory until you stop the process. Restarting the script requires reconfiguring the rules.
+
+## Troubleshooting
+
+* **`TELETHON_API_ID and TELETHON_API_HASH must be set.`** – make sure both environment variables are exported before running `python bot.py`.
+* **`TELEGRAM_OWNER_IDS must provide at least one user ID when TELEGRAM_BOT_COOKIE is set.`** – bot mode requires a list of authorized controllers.
+* **Entity resolution failures** – ensure the account has joined the source and destination chats and that you provide valid IDs/usernames when prompted.
+
