# Time helpers and CLI formatting helpers (no blockchain logic).

from datetime import datetime, timezone
from typing import Dict, List, Optional


def utc_epoch() -> float:
    # Return the current UTC timestamp as a float.
    return datetime.now(timezone.utc).timestamp()


def utc_now_iso() -> str:
    # Return current UTC time as an ISO-8601 string with 'Z'.
    return datetime.now(timezone.utc).astimezone(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def format_timestamp(ts: float) -> str:
    # Format a UTC timestamp as an ISO-8601 string with 'Z'.
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def format_show_cases(cases: List[Dict], reveal: bool) -> str:
    # Format case data into the text shown by 'show cases'.
    lines: List[str] = []
    for entry in cases:
        case_id = entry.get("case_id", "")
        count = entry.get("items", 0)
        lines.append(f"{case_id} ({count} items)")
    return "\n".join(lines)


def format_show_items(items: List[Dict], case_id: Optional[str], reveal: bool) -> str:
    # Format item data into the text shown by 'show items'.
    lines: List[str] = []
    header = f"Items for Case: {case_id}" if case_id else "Items"
    lines.append(header)
    for entry in items:
        iid = entry.get("item_id")
        state = entry.get("state", "")
        owner = entry.get("owner", "")
        lines.append(f"Item {iid}: {state} (owner: {owner})")
    return "\n".join(lines)


def format_history(entries: List[Dict], reveal: bool) -> str:
    # Format history entries into the text shown by 'show history'.
    lines: List[str] = []
    for entry in entries:
        ts = entry.get("timestamp_iso") or format_timestamp(entry.get("timestamp", 0.0))
        case_id = entry.get("case_id", "")
        item_id = entry.get("item_id", "")
        state = entry.get("state", "")
        creator = entry.get("creator", "")
        lines.append(f"{ts}  case={case_id}  item={item_id}  {state} by {creator}")
    return "\n".join(lines)


def format_verify(result: Dict) -> str:
    # Format verify_chain() result dictionary into the CLI output text.
    lines: List[str] = []

    count = result.get("count", 0)
    state = result.get("state", "CLEAN")
    error_kind = result.get("error_kind")

    lines.append(f"> Transactions in blockchain: {count}")
    lines.append(f"> State of blockchain: {'OK' if state == 'CLEAN' else 'ERROR'}")

    if state == "CLEAN":
        return "\n".join(lines)

    lines.append("> Bad block:")
    bad_hash = result.get("found_prev_hash") or result.get("expected_prev_hash")
    lines.append(bad_hash if bad_hash else "NOT FOUND")

    if error_kind in {"HASH_MISMATCH", "DUPLICATE_PARENT"}:
        lines.append("> Parent block:")
        parent_hash = result.get("expected_prev_hash")
        lines.append(parent_hash if parent_hash else "NOT FOUND")

    if error_kind == "DUPLICATE_PARENT":
        lines.append("> Two blocks were found with the same parent.")
    elif error_kind == "ACTION_AFTER_REMOVAL":
        lines.append("> Item checked out or checked in after removal from chain.")
    elif error_kind == "NO_BLOCKS":
        lines.append("> No blocks found in blockchain.")
    elif error_kind == "INVALID_GENESIS":
        lines.append("> Genesis block is invalid.")
    elif error_kind == "DOUBLE_CHECKOUT":
        lines.append("> Item was checked out twice without a checkin.")
    elif error_kind == "DOUBLE_REMOVE":
        lines.append("> Item was removed more than once.")
    elif error_kind == "DUPLICATE_ITEM":
        lines.append("> Duplicate item state detected in blockchain.")
    elif error_kind == "EXCEPTION":
        exc = result.get("exception", "Unknown error")
        lines.append(f"> Internal error during verify: {exc}")

    return "\n".join(lines)


def format_summary(summary: Dict) -> str:
    # Format case summary dictionary into the text shown by 'summary'.
    case_id = summary.get("case_id", "")
    num_items = summary.get("num_items", 0)
    states = summary.get("states", {})

    checked_in = states.get("CHECKEDIN", 0)
    checked_out = states.get("CHECKEDOUT", 0)
    disposed = states.get("DISPOSED", 0)
    destroyed = states.get("DESTROYED", 0)
    released = states.get("RELEASED", 0)

    lines = [
        f"Case Summary for Case ID: {case_id}",
        f"Total Evidence Items: {num_items}",
        f"Checked In: {checked_in}",
        f"Checked Out: {checked_out}",
        f"Disposed: {disposed}",
        f"Destroyed: {destroyed}",
        f"Released: {released}",
    ]
    return "\n".join(lines)
