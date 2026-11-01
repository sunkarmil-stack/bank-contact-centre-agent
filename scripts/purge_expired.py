"""Retention job (run daily as a scheduled container job).

* Long-term memory: expired items are swept by the store's TTL sweeper; this
  job forces a sweep.
* Checkpoints (short-term memory): threads whose last run is older than the
  retention window are deleted.
* Runs and audit records are NOT purged here — they follow the bank's records
  retention schedule in the system of record / WORM archive.

    python -m scripts.purge_expired --days 30
"""

from __future__ import annotations

import argparse
import asyncio
import time

from ccagent.config import Settings
from ccagent.container import build_container


async def main(days: int) -> None:
    async with build_container(Settings.from_env()) as c:
        swept = await c.store.sweep_ttl()
        cutoff = time.time() - days * 86400
        threads = {r.thread_id for r in c.runs.all_runs() if r.updated_at < cutoff}
        for t in threads:
            await c.checkpointer.adelete_thread(t)
        c.audit.append("retention_purge", "retention-job", None, threads_deleted=len(threads), memory_swept=swept)
        print(f"swept {swept} memory items; deleted {len(threads)} checkpoint threads older than {days} days")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=30)
    asyncio.run(main(ap.parse_args().days))
