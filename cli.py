import sys
import argparse
from commands import (
    init_handler, add_handler, checkout_handler, checkin_handler,
    show_cases_handler, show_items_handler, show_history_handler,
    remove_handler, summary_handler, verify_handler, BchocError, ExitCode
)
from timefmt import (
    format_show_cases, format_show_items, format_history,
    format_verify, format_summary, format_timestamp
)
from security import get_item_case_id, get_item_state, get_item_creator, sort_case_items, get_item_owner
from uuid import UUID
from timefmt import utc_epoch

def get_case_item_count(case_id: str) -> int:
    items = sort_case_items(case_id)
    return len(items)

def main():
    parser = argparse.ArgumentParser(prog="bchoc", add_help=True)

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init", help="Initialize blockchain")

    p_add = sub.add_parser("add", help="Add evidence item(s)")
    p_add.add_argument("-c", "--case_id", required=True)
    p_add.add_argument("-i", "--item_id", action="append", required=True, type=int)
    p_add.add_argument("-g", "--creator", required=True)
    p_add.add_argument("-p", "--password", required=True)

    p_checkout = sub.add_parser("checkout", help="Check out item")
    p_checkout.add_argument("-i", "--item_id", required=True, type=int)
    p_checkout.add_argument("-p", "--password", required=True)

    p_checkin = sub.add_parser("checkin", help="Check in item")
    p_checkin.add_argument("-i", "--item_id", required=True, type=int)
    p_checkin.add_argument("-p", "--password", required=True)

    p_sc = sub.add_parser("show", help="Show info")
    p_sc_sub = p_sc.add_subparsers(dest="show_cmd", required=True)

    p_show_cases = p_sc_sub.add_parser("cases", help="Show all cases")
    p_show_cases.add_argument("-p", "--password", required=True)

    p_show_items = p_sc_sub.add_parser("items", help="Show all items in case")
    p_show_items.add_argument("-c", "--case_id", required=True)
    p_show_items.add_argument("-p", "--password", required=True)

    p_history = p_sc_sub.add_parser("history", help="Show history")
    p_history.add_argument("-c", "--case_id", required=False)
    p_history.add_argument("-i", "--item_id", required=False, type=int)
    p_history.add_argument("-n", "--num_entries", type=int)
    p_history.add_argument("-r", "--reverse", action="store_true")
    p_history.add_argument("-p", "--password", required=True)

    p_remove = sub.add_parser("remove", help="Remove evidence item")
    p_remove.add_argument("-i", "--item_id", required=True, type=int)
    p_remove.add_argument("-y", "--why", required=True)
    p_remove.add_argument("-o", "--owner", required=False)
    p_remove.add_argument("-p", "--password", required=True)

    p_summary = sub.add_parser("summary", help="Case summary")
    p_summary.add_argument("-c", "--case_id", required=True)

    sub.add_parser("verify", help="Verify entire blockchain")

    args = parser.parse_args()

    try:
        # INIT
        if args.command == "init":
            code = init_handler()
            if code == ExitCode.OK:
                pass
            sys.exit(code)

        if args.command == "add":
            result = add_handler(
                args.case_id,
                args.item_id,
                args.creator,
                args.password
            )
            code, case_id, timestamps = result
            if code == ExitCode.OK:
                for i, iid in enumerate(args.item_id):
                    print(f"Added item: {iid}")
                    print("Status: CHECKEDIN")
                    print(f"Time of action: {format_timestamp(timestamps[i])}")
            sys.exit(code)

        # CHECKOUT
        if args.command == "checkout":
            result = checkout_handler(args.item_id, args.password)
            code, case_id, timestamp = result
            if code == ExitCode.OK:
                print(f"Case: {case_id}")
                print(f"Checked out item: {args.item_id}")
                print("Status: CHECKEDOUT")
                print(f"Time of action: {format_timestamp(timestamp)}")
            sys.exit(code)

        # CHECKIN
        if args.command == "checkin":
            result = checkin_handler(args.item_id, args.password)
            code, case_id, timestamp = result
            if code == ExitCode.OK:
                print(f"Case: {case_id}")
                print(f"Checked in item: {args.item_id}")
                print("Status: CHECKEDIN")
                print(f"Time of action: {format_timestamp(timestamp)}")
            sys.exit(code)

        # REMOVE
        if args.command == "remove":
            result = remove_handler(args.item_id, args.why, args.owner, args.password)
            code, case_id, timestamp, reason = result
            if code == ExitCode.OK:
                print(f"Case: {case_id}")
                print(f"Removed item: {args.item_id}")
                print(f"Status: {reason}")
                print(f"Time of action: {format_timestamp(timestamp)}")
            sys.exit(code)

        # SHOW
        if args.command == "show":
            if args.show_cmd == "cases":
                cases = show_cases_handler(args.password)
                cases_with_counts = []
                for cid in cases:
                    item_count = get_case_item_count(cid)
                    cases_with_counts.append({"case_id": cid, "items": item_count})
                print(format_show_cases(cases_with_counts, reveal=True))
                sys.exit(ExitCode.OK)

            if args.show_cmd == "items":
                items = show_items_handler(args.case_id, args.password)
                entries = []
                for iid in items:
                    state = get_item_state(iid) or ""
                    owner = get_item_owner(iid) or ""
                    entries.append({"item_id": iid, "state": state, "owner": owner})
                print(format_show_items(entries, args.case_id, reveal=True))
                sys.exit(ExitCode.OK)

            if args.show_cmd == "history":
                hist = show_history_handler(
                    args.case_id,
                    args.item_id,
                    args.num_entries,
                    args.reverse,
                    args.password
                )
                output = format_history(hist, reveal=True)
                if output: 
                    print(output)
                sys.exit(ExitCode.OK)
                            
        # SUMMARY
        if args.command == "summary":
            summary = summary_handler(args.case_id)
            print(format_summary(summary))
            sys.exit(ExitCode.OK)

        # VERIFY
        if args.command == "verify":
            result = verify_handler()
            print(format_verify(result))
            
            if result.get("state") != "CLEAN":
                sys.exit(ExitCode.E_VERIFY)  
            
            sys.exit(ExitCode.OK)

    except BchocError as e:
        print(e.msg)
        sys.exit(e.code)

    except Exception as e:
        print(f"Internal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
