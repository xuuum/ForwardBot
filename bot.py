
diff --git a/bot.py b/bot.py
index 8b137891791fe96927ad78e64b0aad7bded08bdc..e8b313fbde8aab6424793d6f812f5a77927f74b9 100644
--- a/bot.py
+++ b/bot.py
@@ -1 +1,386 @@
+"""Telegram forwarder built with Telethon.
 
+This script can authenticate either as a full user account (a *userbot*) or as
+an ordinary Telegram bot. In both cases the owner can configure forwarding
+rules directly from Telegram. Use the `/forward` command from any dialog
+(Saved Messages is convenient for userbot mode, while a private chat with the
+bot works for bot mode) to walk through the interactive setup:
+
+1. The script asks for a source channel or supergroup.
+2. Then it asks for the destination channel, supergroup, or chat.
+3. Finally it asks whether to forward `all` messages or only `media` (photos and
+   videos).
+
+Each rule forwards new messages that match the selected mode. All rules live in
+memory for the lifetime of the process.
+
+Environment variables
+---------------------
+* ``TELETHON_API_ID`` – required, obtained from https://my.telegram.org.
+* ``TELETHON_API_HASH`` – required, obtained alongside the API ID.
+* ``TELETHON_SESSION`` – optional session file name (defaults to
+  ``userbot_forwarder``).
+* ``TELEGRAM_BOT_COOKIE`` – optional bot token; when provided the client logs
+  in as that bot instead of a user. (A Bot API token looks like
+  ``123456:ABC-DEF``.)
+* ``TELEGRAM_OWNER_IDS`` – optional comma-separated list of Telegram user IDs
+  that are allowed to configure forwarding. This becomes mandatory when running
+  with ``TELEGRAM_BOT_COOKIE`` so that only the specified accounts can issue
+  commands.
+
+Install dependencies with ``pip install telethon`` and run ``python bot.py``.
+The first launch prompts for the login code so the account can authorize the
+session.
+"""
+
+from __future__ import annotations
+
+import asyncio
+import logging
+import os
+from dataclasses import dataclass, field
+from typing import Dict, List, Optional, Set
+
+from telethon import TelegramClient, events
+from telethon.errors import RPCError
+from telethon.tl import types
+from telethon.utils import get_display_name, get_peer_id
+
+
+logger = logging.getLogger(__name__)
+
+
+@dataclass
+class ForwardRule:
+    """Represents a configured forwarding rule."""
+
+    source_id: int
+    source_label: str
+    destination_peer: types.TypeInputPeer
+    destination_label: str
+    mode: str  # "all" or "media"
+
+
+@dataclass
+class SetupState:
+    """Tracks interactive /forward setup per chat."""
+
+    stage: str
+    source_text: Optional[str] = None
+    destination_text: Optional[str] = None
+    ignored_message_ids: Set[int] = field(default_factory=set)
+
+
+forward_rules: List[ForwardRule] = []
+pending_setups: Dict[int, SetupState] = {}
+client: Optional[TelegramClient] = None
+authorized_user_ids: Set[int] = set()
+bot_mode: bool = False
+
+
+def parse_owner_ids(raw_value: Optional[str]) -> Set[int]:
+    """Parse TELEGRAM_OWNER_IDS into a set of integers."""
+
+    result: Set[int] = set()
+    if not raw_value:
+        return result
+
+    for chunk in raw_value.split(","):
+        chunk = chunk.strip()
+        if not chunk:
+            continue
+        try:
+            result.add(int(chunk))
+        except ValueError as error:
+            raise RuntimeError(
+                "TELEGRAM_OWNER_IDS must contain integer IDs separated by commas."
+            ) from error
+    return result
+
+
+def is_authorized_sender(event: events.NewMessage.Event) -> bool:
+    """Return True when the event originates from an allowed controller."""
+
+    sender_id = event.sender_id
+    if bot_mode:
+        return sender_id is not None and sender_id in authorized_user_ids
+
+    if event.out:
+        return True
+
+    return sender_id is not None and sender_id in authorized_user_ids
+
+
+def normalize_identifier(value: str) -> str:
+    """Return a sanitized identifier without surrounding whitespace or '@'."""
+
+    value = value.strip()
+    if value.startswith("@"):
+        value = value[1:]
+    return value
+
+
+def is_photo_or_video(message: types.Message) -> bool:
+    """Return True when the message contains a photo or a video."""
+
+    media = message.media
+    if isinstance(media, types.MessageMediaPhoto):
+        return True
+    if isinstance(media, types.MessageMediaDocument) and message.document:
+        for attribute in message.document.attributes:
+            if isinstance(attribute, types.DocumentAttributeVideo):
+                return True
+    return False
+
+
+async def start_forward_setup(event: events.NewMessage.Event) -> None:
+    """Initiate the /forward setup conversation."""
+
+    global pending_setups
+
+    if not is_authorized_sender(event):
+        return
+
+    chat_id = event.chat_id
+    state = SetupState(stage="source")
+    state.ignored_message_ids.add(event.message.id)
+    pending_setups[chat_id] = state
+
+    prompt = await event.respond(
+        "Please provide the source channel or supergroup ID/username."
+    )
+    state.ignored_message_ids.add(prompt.id)
+
+
+async def process_setup_response(event: events.NewMessage.Event) -> None:
+    """Handle responses during /forward setup."""
+
+    if not is_authorized_sender(event):
+        return
+
+    chat_id = event.chat_id
+    state = pending_setups.get(chat_id)
+    if state is None:
+        return
+
+    message_id = event.message.id
+    if message_id in state.ignored_message_ids:
+        state.ignored_message_ids.discard(message_id)
+        return
+
+    text = event.raw_text.strip()
+    if not text:
+        prompt = await event.respond("Please send a non-empty value or /cancel.")
+        state.ignored_message_ids.add(prompt.id)
+        return
+
+    if text.lower() == "/cancel":
+        pending_setups.pop(chat_id, None)
+        prompt = await event.respond("Forwarding setup cancelled.")
+        state.ignored_message_ids.add(prompt.id)
+        return
+
+    if state.stage == "source":
+        state.source_text = normalize_identifier(text)
+        state.stage = "destination"
+        prompt = await event.respond(
+            "Got it! Now send the destination ID/username to forward into."
+        )
+        state.ignored_message_ids.add(prompt.id)
+        return
+
+    if state.stage == "destination":
+        state.destination_text = normalize_identifier(text)
+        state.stage = "mode"
+        prompt = await event.respond(
+            "Great! Reply with 'all' to forward every message or 'media' to forward "
+            "only photos and videos."
+        )
+        state.ignored_message_ids.add(prompt.id)
+        return
+
+    if state.stage == "mode":
+        mode = text.lower()
+        if mode not in {"all", "media"}:
+            prompt = await event.respond("Invalid mode. Please reply with 'all' or 'media'.")
+            state.ignored_message_ids.add(prompt.id)
+            return
+
+        await finalize_rule(event, state, mode)
+        pending_setups.pop(chat_id, None)
+
+
+async def finalize_rule(
+    event: events.NewMessage.Event, state: SetupState, mode: str
+) -> None:
+    """Validate inputs, store the rule, and inform the user."""
+
+    assert client is not None  # Guard for type checkers.
+
+    if state.source_text is None or state.destination_text is None:
+        prompt = await event.respond("Setup is incomplete. Please start again with /forward.")
+        state.ignored_message_ids.add(prompt.id)
+        return
+
+    try:
+        source_entity = await client.get_entity(state.source_text)
+        destination_entity = await client.get_entity(state.destination_text)
+    except (ValueError, RPCError) as error:  # Entity lookup failed.
+        logger.warning("Failed to resolve entity: %s", error)
+        prompt = await event.respond(
+            "Unable to resolve one of the chats. Check that you joined both and try again."
+        )
+        state.ignored_message_ids.add(prompt.id)
+        return
+
+    try:
+        destination_peer = await client.get_input_entity(destination_entity)
+    except (ValueError, RPCError) as error:
+        logger.warning("Failed to obtain destination input peer: %s", error)
+        prompt = await event.respond("Could not prepare the destination for forwarding.")
+        state.ignored_message_ids.add(prompt.id)
+        return
+
+    source_id = get_peer_id(source_entity)
+    rule = ForwardRule(
+        source_id=source_id,
+        source_label=get_display_name(source_entity) or state.source_text,
+        destination_peer=destination_peer,
+        destination_label=get_display_name(destination_entity) or state.destination_text,
+        mode=mode,
+    )
+    forward_rules.append(rule)
+
+    summary = (
+        f"Forwarding rule created!\n"
+        f"Source: {rule.source_label}\n"
+        f"Destination: {rule.destination_label}\n"
+        f"Mode: {'all messages' if mode == 'all' else 'photos and videos only'}"
+    )
+    prompt = await event.respond(summary)
+    state.ignored_message_ids.add(prompt.id)
+    logger.info(
+        "Created rule source_id=%s destination=%s mode=%s",
+        rule.source_id,
+        rule.destination_label,
+        rule.mode,
+    )
+
+
+async def handle_incoming_message(event: events.NewMessage.Event) -> None:
+    """Forward new messages that satisfy stored rules."""
+
+    if not forward_rules:
+        return
+
+    message = event.message
+    if message is None or event.chat_id is None:
+        return
+
+    for rule in forward_rules:
+        if event.chat_id != rule.source_id:
+            continue
+
+        if rule.mode == "media" and not is_photo_or_video(message):
+            continue
+
+        try:
+            await event.client.forward_messages(rule.destination_peer, message)
+        except RPCError as error:
+            logger.warning("Failed to forward message to %s: %s", rule.destination_label, error)
+
+
+def build_client() -> TelegramClient:
+    """Create and return the Telethon client instance."""
+
+    api_id_text = os.getenv("TELETHON_API_ID")
+    api_hash = os.getenv("TELETHON_API_HASH")
+    session_name = os.getenv("TELETHON_SESSION", "userbot_forwarder")
+
+    if not api_id_text or not api_hash:
+        raise RuntimeError("TELETHON_API_ID and TELETHON_API_HASH must be set.")
+
+    try:
+        api_id = int(api_id_text)
+    except ValueError as error:
+        raise RuntimeError("TELETHON_API_ID must be an integer.") from error
+
+    client = TelegramClient(session_name, api_id, api_hash)
+    client.add_event_handler(start_forward_setup, events.NewMessage(pattern=r"^/forward$"))
+    client.add_event_handler(process_setup_response, events.NewMessage())
+    client.add_event_handler(handle_incoming_message, events.NewMessage(incoming=True))
+    return client
+
+
+async def async_main() -> None:
+    """Async entry point."""
+
+    global client
+    global authorized_user_ids
+    global bot_mode
+
+    logging.basicConfig(
+        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
+        level=logging.INFO,
+    )
+
+    client = build_client()
+
+    bot_token_raw = os.getenv("TELEGRAM_BOT_COOKIE")
+    bot_token = bot_token_raw.strip() if bot_token_raw else None
+    owner_env = os.getenv("TELEGRAM_OWNER_IDS")
+    configured_owner_ids = parse_owner_ids(owner_env)
+
+    async with client:
+        if bot_token:
+            bot_mode = True
+            if not configured_owner_ids:
+                raise RuntimeError(
+                    "TELEGRAM_OWNER_IDS must provide at least one user ID when "
+                    "TELEGRAM_BOT_COOKIE is set."
+                )
+            await client.start(bot_token=bot_token)
+        else:
+            await client.start()
+
+        me = await client.get_me()
+        if me is None:
+            raise RuntimeError("Unable to determine the current account.")
+
+        if bot_mode:
+            authorized_user_ids = configured_owner_ids
+        else:
+            authorized_user_ids = configured_owner_ids | {me.id}
+
+        logger.info("Logged in as %s", get_display_name(me))
+
+        notification = (
+            "Forwarder is online. Send /forward here to configure a rule."
+        )
+
+        if bot_mode:
+            for user_id in sorted(authorized_user_ids):
+                try:
+                    await client.send_message(user_id, notification)
+                except RPCError as error:
+                    logger.warning("Failed to notify owner %s: %s", user_id, error)
+        else:
+            try:
+                await client.send_message(
+                    me,  # Send into Saved Messages for convenience.
+                    notification,
+                )
+            except RPCError as error:
+                logger.warning("Failed to send startup message to self: %s", error)
+
+        await client.run_until_disconnected()
+
+
+def main() -> None:
+    """Run the Telethon userbot."""
+
+    asyncio.run(async_main())
+
+
+if __name__ == "__main__":
+    main()
