from arpie.models import Database
from arpie.seeder import is_seeded, seed_database, unseed_database


def test_seeder_lifecycle(tmp_path):
    db_file = str(tmp_path / "test_seeder.db")
    db = Database(db_file)

    assert not is_seeded(db)

    result = seed_database(db)
    assert result["status"] == "seeded"
    assert result["sessions_count"] >= 3
    assert result["events_count"] >= 4
    assert is_seeded(db)

    sessions = db.get_operator_sessions()
    assert len(sessions) >= 3

    unseed_res = unseed_database(db)
    assert unseed_res["status"] == "cleared"
    assert unseed_res["removed_sessions"] >= 3
    assert not is_seeded(db)
