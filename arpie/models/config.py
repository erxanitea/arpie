from ._typing import MixinBase


class ConfigMixin(MixinBase):

    def get_config(self, key: str, default: str = "") -> str:
        with self.cursor() as cur:
            cur.execute("SELECT value FROM operator_config WHERE key = ?", (key,))
            row = cur.fetchone()
            return str(row["value"]) if row else default

    def set_config(self, key: str, value: str):
        with self.cursor() as cur:
            cur.execute(
                "INSERT INTO operator_config (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
