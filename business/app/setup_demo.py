import argparse
import json
from pathlib import Path
from time import time

from .db import create_session, initialize, seed, write_transaction
from .main import database_path


def main() -> None:
    parser = argparse.ArgumentParser(description='Initialize a SQLite database for synthetic campus tasks')
    parser.add_argument('--db', type=Path, default=database_path())
    parser.add_argument('--now', type=int, default=int(time()))
    parser.add_argument('--session-for', choices=('V001', 'V002', 'V003', 'V004'))
    args = parser.parse_args()
    initialize(args.db)
    seed(args.db, args.now)
    if args.session_for:
        with write_transaction(args.db) as conn:
            session = create_session(conn, args.session_for, args.now)
        print(json.dumps(session))
    else:
        print(f'Synthetic database ready: {args.db}')


if __name__ == '__main__':
    main()
