#!/usr/bin/python
from functools import partial

from confluent_kafka import Consumer as KafkaConsumer
from prometheus_client import start_http_server

from api.cache import init_cache
from app import create_app
from app.environment import RuntimeEnvironment
from app.logging import get_logger
from app.queue.event_producer import EventProducer
from app.queue.host_mq import add_host
from app.queue.host_mq import event_loop
from app.queue.host_mq import handle_message
from app.queue.host_mq import update_system_profile
from lib.handlers import ShutdownHandler
from lib.handlers import register_shutdown

logger = get_logger("host_mq_service")


def main():
    application = create_app(RuntimeEnvironment.SERVICE)
    config = application.app.config["INVENTORY_CONFIG"]
    init_cache(config, application)
    start_http_server(config.metrics_port)

    topic_to_handler = {config.host_ingress_topic: add_host, config.system_profile_topic: update_system_profile}

    consumer = KafkaConsumer(
        {
            "group.id": config.host_ingress_consumer_group,
            "bootstrap.servers": config.bootstrap_servers,
            "auto.offset.reset": "earliest",
            **config.kafka_consumer,
        }
    )
    consumer.subscribe([config.kafka_consumer_topic])
    consumer_shutdown = partial(consumer.close, autocommit=True)
    register_shutdown(consumer_shutdown, "Closing consumer")

    event_producer = EventProducer(config, config.event_topic)
    register_shutdown(event_producer.close, "Closing producer")

    notification_event_producer = EventProducer(config, config.notification_topic)
    register_shutdown(notification_event_producer.close, "Closing notification producer")

    shutdown_handler = ShutdownHandler()
    shutdown_handler.register()

    message_handler = partial(
        handle_message,
        message_operation=topic_to_handler[config.kafka_consumer_topic],
        notification_event_producer=notification_event_producer,
    )

    event_loop(
        consumer,
        application.app,
        event_producer,
        notification_event_producer,
        message_handler,
        shutdown_handler.shut_down,
    )


if __name__ == "__main__":
    main()
