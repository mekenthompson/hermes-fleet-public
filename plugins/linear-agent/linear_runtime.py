"""Async runtime adapter for one profile-local Linear worker."""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from pathlib import Path

from .linear_agent import LinearWorker, QueuedLinearJob


class ProfileLinearRuntime:
    """Admit sessions immediately while one FIFO executor runs agent turns."""

    def __init__(
        self,
        worker: LinearWorker,
        ingress_database: Path,
        execute: Callable[[str, str], Awaitable[str]],
        emit: Callable[[str, str, str], object],
        *,
        prepare: Callable[[str], Awaitable[object]] | None = None,
    ) -> None:
        self._worker = worker
        self._ingress_database = ingress_database
        self._execute = execute
        self._emit = emit
        self._prepare = prepare or self._no_prepare
        self._active_task: asyncio.Task[bool] | None = None
        self._active_job: QueuedLinearJob | None = None

    @staticmethod
    async def _no_prepare(_session_key: str) -> None:
        return None

    async def _flush_one(self) -> bool:
        try:
            return await asyncio.to_thread(
                self._worker.dispatch_outbox,
                lambda session_id, activity_type, body: self._emit(
                    session_id,
                    activity_type,
                    body,
                ),
            )
        except Exception:  # noqa: BLE001 - external-send ambiguity is quarantined
            return False

    async def _flush_all(self) -> bool:
        flushed = False
        while await self._flush_one():
            flushed = True
        return flushed

    async def _execute_job(self, job: QueuedLinearJob) -> bool:
        try:
            response = str(
                await self._execute(job.hermes_session_key, job.prompt)
            )
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - emit only a redacted terminal response
            await asyncio.to_thread(self._worker.fail_job, job)
        else:
            await asyncio.to_thread(self._worker.complete_job, job, response)
        return True

    async def _collect_finished_task(self) -> bool:
        task = self._active_task
        if task is None or not task.done():
            return False
        self._active_task = None
        self._active_job = None
        return await task

    async def run_once(self) -> bool:
        completed = await self._collect_finished_task()
        imported = await asyncio.to_thread(
            self._worker.import_from_ingress_once,
            self._ingress_database,
        )
        admitted, _admitted_job = await asyncio.to_thread(self._worker.admit_once)
        rejected = await asyncio.to_thread(self._worker.reauthorize_recoverable)
        # Re-authorize durable recovery work before any pending admission
        # side effects can be flushed.
        flushed = await self._flush_all()
        # Always prepare the oldest durable queue entry. A newly imported event
        # must not overtake work admitted before a restart.
        job = await asyncio.to_thread(self._worker.next_unprepared)
        if job is not None:
            try:
                await self._prepare(job.hermes_session_key)
                await asyncio.to_thread(self._worker.mark_prepared, job)
            except Exception:  # noqa: BLE001 - preparation failures are redacted
                # Preserve Linear's required acknowledgement ordering even when
                # Hermes session preparation fails.
                flushed = await self._flush_all() or flushed
                await asyncio.to_thread(self._worker.fail_job, job)
                job = None

        flushed = await self._flush_all() or flushed
        started = False
        if self._active_task is None:
            queued = await asyncio.to_thread(self._worker.claim_prepared)
            if queued is not None:
                flushed = await self._flush_all() or flushed
                ready = await asyncio.to_thread(self._worker.execution_ready, queued)
                if not ready:
                    suppressed = await asyncio.to_thread(
                        self._worker.execution_suppressed,
                        queued,
                    )
                    if suppressed:
                        await asyncio.to_thread(self._worker.cancel_job, queued)
                    else:
                        await asyncio.to_thread(self._worker.release_claim, queued)
                else:
                    self._active_job = queued
                    self._active_task = asyncio.create_task(self._execute_job(queued))
                    started = True
                    await asyncio.sleep(0)
                    completed = await self._collect_finished_task() or completed
                    if completed:
                        flushed = await self._flush_all() or flushed
        return imported or admitted or rejected or started or completed or flushed

    async def shutdown(self) -> None:
        """Cancel an in-flight turn; restart recovery quarantines its delivery."""
        task = self._active_task
        job = self._active_job
        self._active_task = None
        self._active_job = None
        if task is None:
            return
        if task.done():
            await task
            await self._flush_all()
            return
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        if job is not None:
            await asyncio.to_thread(self._worker.fail_job, job)
            await self._flush_all()
