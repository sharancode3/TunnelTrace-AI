"""Celery application configuration for asynchronous background task execution."""

from celery import Celery  # type: ignore[import-untyped]

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "tunneltrace_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.health_tasks", "app.workers.protocol_tasks"],
)

celery_app.conf.update(
    task_serializer=settings.CELERY_TASK_SERIALIZER,
    result_serializer=settings.CELERY_RESULT_SERIALIZER,
    accept_content=settings.CELERY_ACCEPT_CONTENT,
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes max per task
    task_soft_time_limit=270,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
)
