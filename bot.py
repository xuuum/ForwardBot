from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from dotenv import load_dotenv
from telethon import TelegramClient, events
from telethon.errors import (
    PasswordHashInvalidError,
    PhoneCodeExpiredError,
    PhoneCodeInvalidError,
    RPCError,
    SessionPasswordNeededError,
)
from telethon.tl import types
from telethon.utils import get_display_name, get_peer_id


logger = logging.getLogger(__name__)


@dataclass
class ForwardRule:
    """Represents a configured forwarding rule."""

    source_id: int
    source_label: str
    destination_peer: types.TypeInputPeer
    destination_label: str
    mode: str  # "all" or "media"


@dataclass
class SetupState:
    """Tracks interactive /forward setup per chat."""

    stage: str
    source_id: Optional[int] = None
    destination_id: Optional[int] = None


forward_rules: List[ForwardRule] = []
pending_setups: Dict[int, SetupState] = {}
user_client: Optional[TelegramClient] = None
bot_client: Optional[TelegramClient] = None
authorized_user_ids: Set[int] = set()
controller_bot_token: Optional[str] = None
login_state: Optional["LoginState"] = None
login_complete_event: Optional[asyncio.Event] = None


@dataclass
class LoginState:
    """Holds state while the user account authorizes the session."""

    phone_number: str
    phone_code_hash: str
    awaiting_code: bool = True
    awaiting_password: bool = False


def parse_owner_ids(raw_value: Optional[str]) -> Set[int]:
    """Parse TELEGRAM_OWNER_IDS into a set of integers."""

    result: Set[int] = set()
    if not raw_value:
        return result

    for chunk in raw_value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            result.add(int(chunk))
        except ValueError as error:
            raise RuntimeError(
                "TELEGRAM_OWNER_IDS must contain integer IDs separated by commas."
            ) from error
    return result


def is_authorized_sender(event: events.NewMessage.Event) -> bool:
    """Return True when the event originates from an allowed controller."""

    sender_id = event.sender_id
    return sender_id is not None and sender_id in authorized_user_ids


def is_photo_or_video(message: types.Message) -> bool:
    """Return True when the message contains a photo or a video."""

    media = message.media
    if isinstance(media, types.MessageMediaPhoto):
        return True
    if isinstance(media, types.MessageMediaDocument) and message.document:
        for attribute in message.document.attributes:
            if isinstance(attribute, types.DocumentAttributeVideo):
                return True
    return False


async def start_forward_setup(event: events.NewMessage.Event) -> None:
    """Initiate the /forward setup conversation."""

    if not is_authorized_sender(event):
        return

    chat_id = event.chat_id
    state = SetupState(stage="source")
    pending_setups[chat_id] = state

    await event.respond(
        "Please provide the numeric chat ID of the source channel or group.\n"
        "Send /listchats to view known IDs from the user account or /cancel to abort."
    )


async def process_setup_response(event: events.NewMessage.Event) -> None:
    """Handle responses during /forward setup."""

    if not is_authorized_sender(event):
        return

    chat_id = event.chat_id
    state = pending_setups.get(chat_id)
    if state is None:
        return

    text = event.raw_text.strip()
    if not text:
        await event.respond("Please send a non-empty value or /cancel.")
        return

    if text.lower() == "/cancel":
        pending_setups.pop(chat_id, None)
        await event.respond("Forwarding setup cancelled.")
        return

    if text.startswith("/") and text.lower() != "/cancel":
        await event.respond(
            "Finish the current setup first or send /cancel to stop configuring."
        )
        return

    if state.stage == "source":
        try:
            state.source_id = int(text)
        except ValueError:
            await event.respond("Source IDs must be integers like -1001234567890.")
            return

        state.stage = "destination"
        await event.respond(
            "Got it! Now send the numeric chat ID for the destination channel or chat."
        )
        return

    if state.stage == "destination":
        try:
            state.destination_id = int(text)
        except ValueError:
            await event.respond("Destination IDs must be integers like -1001234567890.")
            return

        state.stage = "mode"
        await event.respond(
            "Great! Reply with 'all' to forward every message or 'media' to forward "
            "only photos and videos."
        )
        return

    if state.stage == "mode":
        mode = text.lower()
        if mode not in {"all", "media"}:
            await event.respond("Invalid mode. Please reply with 'all' or 'media'.")
            return

        await finalize_rule(event, state, mode)
        pending_setups.pop(chat_id, None)


async def list_known_chats(event: events.NewMessage.Event) -> None:
    """Send a list of dialogs known to the user account."""

    if not is_authorized_sender(event):
        return

    if user_client is None:
        await event.respond("User client is not ready yet. Try again shortly.")
        return

    lines: List[str] = []
    async for dialog in user_client.iter_dialogs():
        entity = dialog.entity
        if entity is None:
            continue
        try:
            peer_id = get_peer_id(entity)
        except TypeError:
            continue
        name = get_display_name(entity) or "(no title)"
        lines.append(f"{peer_id}: {name}")

    if not lines:
        await event.respond("No dialogs found. Make sure the user account has joined chats.")
        return

    message_chunks: List[str] = []
    current_chunk: List[str] = []
    current_length = 0
    for line in lines:
        if current_length + len(line) + 1 > 3500:
            message_chunks.append("\n".join(current_chunk))
            current_chunk = [line]
            current_length = len(line)
        else:
            current_chunk.append(line)
            current_length += len(line) + 1
    if current_chunk:
        message_chunks.append("\n".join(current_chunk))

    for chunk in message_chunks:
        await event.respond(chunk)


async def finalize_rule(
    event: events.NewMessage.Event, state: SetupState, mode: str
) -> None:
    """Validate inputs, store the rule, and inform the user."""

    assert user_client is not None  # Guard for type checkers.

    if state.source_id is None or state.destination_id is None:
        await event.respond("Setup is incomplete. Please start again with /forward.")
        return

    try:
        source_entity = await user_client.get_entity(state.source_id)
        destination_entity = await user_client.get_entity(state.destination_id)
    except (ValueError, RPCError) as error:  # Entity lookup failed.
        logger.warning("Failed to resolve entity: %s", error)
        await event.respond(
            "Unable to resolve one of the chats. Check that you joined both and try again."
        )
        return

    try:
        destination_peer = await user_client.get_input_entity(destination_entity)
    except (ValueError, RPCError) as error:
        logger.warning("Failed to obtain destination input peer: %s", error)
        await event.respond("Could not prepare the destination for forwarding.")
        return

    source_id = get_peer_id(source_entity)
    rule = ForwardRule(
        source_id=source_id,
        source_label=get_display_name(source_entity) or str(state.source_id),
        destination_peer=destination_peer,
        destination_label=get_display_name(destination_entity)
        or str(state.destination_id),
        mode=mode,
    )
    forward_rules.append(rule)

    summary = (
        f"Forwarding rule created!\n"
        f"Source: {rule.source_label}\n"
        f"Destination: {rule.destination_label}\n"
        f"Mode: {'all messages' if mode == 'all' else 'photos and videos only'}"
    )
    await event.respond(summary)
    logger.info(
        "Created rule source_id=%s destination=%s mode=%s",
        rule.source_id,
        rule.destination_label,
        rule.mode,
    )


async def handle_incoming_message(event: events.NewMessage.Event) -> None:
    """Forward new messages that satisfy stored rules."""

    if not forward_rules:
        return

    message = event.message
    if message is None or event.chat_id is None:
        return

    for rule in forward_rules:
        if event.chat_id != rule.source_id:
            continue

        if rule.mode == "media" and not is_photo_or_video(message):
            continue

        try:
            await event.client.forward_messages(rule.destination_peer, message)
        except RPCError as error:
            logger.warning(
                "Failed to forward message to %s: %s", rule.destination_label, error
            )


def build_clients() -> None:
    """Instantiate Telethon clients for the userbot and controller bot."""

    global user_client
    global bot_client
    global controller_bot_token

    load_dotenv()

    api_id_text = os.getenv("TELETHON_API_ID")
    api_hash = os.getenv("TELETHON_API_HASH")
    session_name = os.getenv("TELETHON_SESSION", "userbot_forwarder")
    bot_token_raw = os.getenv("TELEGRAM_BOT_COOKIE")

    if not api_id_text or not api_hash:
        raise RuntimeError("TELETHON_API_ID and TELETHON_API_HASH must be set.")

    if not bot_token_raw:
        raise RuntimeError("TELEGRAM_BOT_COOKIE must be provided for bot control.")

    try:
        api_id = int(api_id_text)
    except ValueError as error:
        raise RuntimeError("TELETHON_API_ID must be an integer.") from error

    controller_bot_token = bot_token_raw.strip()
    if not controller_bot_token:
        raise RuntimeError("TELEGRAM_BOT_COOKIE cannot be empty.")

    user_client = TelegramClient(session_name, api_id, api_hash)
    user_client.add_event_handler(
        handle_incoming_message, events.NewMessage(incoming=True)
    )

    bot_session = f"{session_name}_controller_bot"
    bot_client = TelegramClient(bot_session, api_id, api_hash)
    bot_client.add_event_handler(
        start_forward_setup,
        events.NewMessage(pattern=r"^/forward$", incoming=True),
    )
    bot_client.add_event_handler(
        list_known_chats,
        events.NewMessage(pattern=r"^/listchats$", incoming=True),
    )
    bot_client.add_event_handler(
        process_setup_response, events.NewMessage(incoming=True)
    )
    bot_client.add_event_handler(
        handle_login_messages,
        events.NewMessage(pattern=r"^/(code|password|resendcode)\b", incoming=True),
    )


async def handle_login_messages(event: events.NewMessage.Event) -> None:
    """Process login commands sent to the controller bot."""

    if not is_authorized_sender(event):
        return

    assert user_client is not None and bot_client is not None

    if login_state is None:
        await event.respond("No login is pending. The userbot is already authorized.")
        return

    command, *rest = event.raw_text.strip().split(maxsplit=1)
    command = command.lower()

    if command == "/code":
        if not login_state.awaiting_code:
            await event.respond(
                "A login code is not required right now. Send /resendcode if you need a new code."
            )
            return

        if not rest:
            await event.respond("Send /code followed by the digits that Telegram sent you.")
            return

        code = rest[0].strip()
        if not code:
            await event.respond("The code cannot be empty. Please resend with the digits.")
            return

        try:
            await user_client.sign_in(
                phone=login_state.phone_number,
                code=code,
                phone_code_hash=login_state.phone_code_hash,
            )
        except SessionPasswordNeededError:
            login_state.awaiting_code = False
            login_state.awaiting_password = True
            await event.respond(
                "This account has a two-step verification password. Reply with /password YOUR_PASSWORD."
            )
            return
        except PhoneCodeInvalidError:
            await event.respond(
                "The code was invalid. Double-check and resend, or use /resendcode for a new one."
            )
            return
        except PhoneCodeExpiredError:
            await event.respond("That code expired. Use /resendcode to request a new one.")
            return
        except RPCError as error:
            logger.warning("Failed to sign in with provided code: %s", error)
            await event.respond(
                "Login failed due to an unexpected error. Try /resendcode for a new code."
            )
            return

        await finalize_login(event)
        return

    if command == "/password":
        if not login_state.awaiting_password:
            await event.respond(
                "A password is not required right now. Provide a login code with /code."
            )
            return

        if not rest:
            await event.respond("Send /password followed by your two-step verification password.")
            return

        password = rest[0]
        try:
            await user_client.sign_in(password=password)
        except PasswordHashInvalidError:
            await event.respond("Incorrect password. Please try again.")
            return
        except RPCError as error:
            logger.warning("Password sign-in failed: %s", error)
            await event.respond("Unable to complete login. Please try again.")
            return

        await finalize_login(event)
        return

    if command == "/resendcode":
        try:
            code = await user_client.send_code_request(login_state.phone_number)
        except RPCError as error:
            logger.warning("Failed to resend login code: %s", error)
            await event.respond("Unable to resend the code right now. Try again later.")
            return

        login_state.phone_code_hash = code.phone_code_hash
        login_state.awaiting_code = True
        login_state.awaiting_password = False
        await event.respond("A new login code was sent. Use /code to submit it here.")
        return


async def finalize_login(event: events.NewMessage.Event) -> None:
    """Complete the login flow after a code or password succeeds."""

    assert login_complete_event is not None and bot_client is not None

    global login_state

    login_state = None
    await event.respond("Login successful! The userbot is now authorized.")
    login_complete_event.set()

    sender_id = event.sender_id
    for user_id in sorted(authorized_user_ids):
        if user_id == sender_id:
            continue
        try:
            await bot_client.send_message(
                user_id, "Login complete. The userbot is now connected."
            )
        except (RPCError, ValueError) as error:
            logger.warning(
                "Failed to broadcast login success to %s: %s", user_id, error
            )


async def ensure_user_authorized() -> None:
    """Make sure the user client is ready, requesting codes via Telegram when needed."""

    assert user_client is not None and bot_client is not None and login_complete_event is not None

    await user_client.connect()

    if await user_client.is_user_authorized():
        await user_client.start()
        login_complete_event.set()
        return

    phone_number = os.getenv("TELETHON_PHONE_NUMBER")
    if not phone_number:
        raise RuntimeError(
            "Set TELETHON_PHONE_NUMBER to allow Telegram-based login when no session exists."
        )

    code = await user_client.send_code_request(phone_number)

    global login_state
    login_state = LoginState(phone_number=phone_number, phone_code_hash=code.phone_code_hash)
    login_complete_event.clear()

    message = (
        "Userbot authorization required. Telegram sent a login code to the configured "
        "account. Reply here with /code <digits>."
    )
    for user_id in sorted(authorized_user_ids):
        try:
            await bot_client.send_message(user_id, message)
        except (RPCError, ValueError) as error:
            logger.warning(
                "Failed to deliver login prompt to owner %s: %s", user_id, error
            )

    await login_complete_event.wait()
    await user_client.start()


async def async_main() -> None:
    """Async entry point."""

    global user_client
    global bot_client
    global authorized_user_ids
    global controller_bot_token
    global login_complete_event

    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )

    build_clients()

    owner_env = os.getenv("TELEGRAM_OWNER_IDS")
    configured_owner_ids = parse_owner_ids(owner_env)

    if not configured_owner_ids:
        raise RuntimeError(
            "TELEGRAM_OWNER_IDS must contain at least one integer user ID."
        )

    assert (
        user_client is not None and bot_client is not None and controller_bot_token
    )

    authorized_user_ids = configured_owner_ids
    login_complete_event = asyncio.Event()

    await bot_client.start(bot_token=controller_bot_token)
    bot_task = asyncio.create_task(bot_client.run_until_disconnected())
    user_task: Optional[asyncio.Task[None]] = None

    try:
        await ensure_user_authorized()

        me = await user_client.get_me()
        bot_info = await bot_client.get_me()
        if me is None or bot_info is None:
            raise RuntimeError("Failed to determine account identities.")

        logger.info(
            "Userbot logged in as %s; bot controller is @%s",
            get_display_name(me),
            getattr(bot_info, "username", None) or bot_info.id,
        )

        notification = (
            "Forwarder is online. Use /forward with this bot to configure a rule."
        )

        for user_id in sorted(authorized_user_ids):
            try:
                await bot_client.send_message(user_id, notification)
            except RPCError as error:
                logger.warning("Failed to notify owner %s: %s", user_id, error)

        user_task = asyncio.create_task(user_client.run_until_disconnected())
        await asyncio.gather(bot_task, user_task)
    finally:
        bot_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await bot_task
        if user_task is not None:
            user_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await user_task
        await user_client.disconnect()
        await bot_client.disconnect()


def main() -> None:
    """Run the Telethon userbot."""

    asyncio.run(async_main())


if __name__ == "__main__":
    main()
