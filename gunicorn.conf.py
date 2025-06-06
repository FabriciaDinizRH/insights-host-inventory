from prometheus_flask_exporter.multiprocess import GunicornPrometheusMetrics

from app.config import Config
from app.environment import RuntimeEnvironment


def when_ready(server):  # noqa: ARG001, needed by gunicorn
    config = Config(RuntimeEnvironment.SERVER)
    GunicornPrometheusMetrics.start_http_server_when_ready(config.metrics_port)


def child_exit(server, worker):  # noqa: ARG001, needed by gunicorn
    GunicornPrometheusMetrics.mark_process_dead_on_child_exit(worker.pid)
