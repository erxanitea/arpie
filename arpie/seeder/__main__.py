import argparse
import sys
from ..config import CONFIG
from ..models import Database
from .service import is_seeded, seed_database, unseed_database


def main():
    parser = argparse.ArgumentParser(description="Arpie Evaluation Dataset Seeder")
    parser.add_argument("--seed", action="store_true", help="Seed realistic evaluation data into SQLite database")
    parser.add_argument("--clear", "--unseed", action="store_true", dest="clear", help="Remove all seeded records from database")
    parser.add_argument("--status", action="store_true", help="Check if database currently contains seeded records")
    parser.add_argument("--user", "--email", dest="user", default="eradumangcas7@gmail.com", help="Operator email or username to associate seeded data with (default: eradumangcas7@gmail.com)")
    args = parser.parse_args()

    db = Database(CONFIG.db_path)

    if args.clear:
        result = unseed_database(db)
        print(f"[+] Successfully purged seeded records: {result['removed_sessions']} sessions removed.")
    elif args.seed:
        result = seed_database(db, user_identifier=args.user)
        op_info = f" (operator_id: {result.get('operator_id')}, user: {args.user})" if result.get('operator_id') else ""
        print(f"[+] Successfully seeded evaluation dataset: {result['sessions_count']} sessions, {result['events_count']} events created{op_info}.")
    elif args.status:
        status = is_seeded(db)
        print(f"[i] Seeded status: {'ACTIVE (Seeded records present)' if status else 'CLEAN (No seeded records)'}")
    else:
        status = is_seeded(db)
        print(f"Current database status: {'SEEDED' if status else 'CLEAN'}")
        print("Usage: python -m arpie.seeder [--seed | --clear | --status]")


if __name__ == "__main__":
    main()
