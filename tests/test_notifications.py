import json

import pytest

from app.exceptions import ValidationException
from tests.helpers.mq_utils import assert_system_registered_notification_is_valid
from tests.helpers.test_utils import generate_uuid
from tests.helpers.test_utils import minimal_host
from tests.helpers.test_utils import SYSTEM_IDENTITY

OWNER_ID = SYSTEM_IDENTITY["system"]["cn"]


# New System Registered
def test_add_basic_host_success(mq_create_or_update_host, notification_event_producer_mock):
    """
    Tests notification production after adding a host
    """
    expected_insights_id = generate_uuid()

    host = minimal_host(
        account=SYSTEM_IDENTITY["account_number"],
        insights_id=expected_insights_id,
    )

    mq_create_or_update_host(host, return_all_data=True)

    assert_system_registered_notification_is_valid(notification_event_producer_mock, host)


def test_new_system_notification_fields(mq_create_or_update_host, notification_event_producer_mock):
    expected_insights_id = generate_uuid()

    host = minimal_host(
        account=SYSTEM_IDENTITY["account_number"],
        insights_id=expected_insights_id,
        system_profile={
            "operating_system": {"name": "RHEL", "major": 8, "minor": 6},
        },
    )

    mq_create_or_update_host(host, return_all_data=True)
    notification = json.loads(notification_event_producer_mock.event)

    assert_system_registered_notification_is_valid(notification_event_producer_mock, host)

    assert notification["context"]["rhel_version"] == "8.6"
    assert notification["account_id"] == SYSTEM_IDENTITY["account_number"]


# this test should pass, RHINENG-11348 was created to fix this behavior

# def test_add_host_fail(mocker):
#     """
#     Test new system notification is not produced after add host fails
#     """
#     invalid_message = json.dumps({"operation": "add_host", "NOTdata": {}})  # Missing data field

#     mock_event_producer = mocker.Mock()
#     mock_notification_event_producer = mocker.Mock()

#     with pytest.raises(marshmallow.exceptions.ValidationError):
#         handle_message(invalid_message, mock_event_producer, mock_notification_event_producer)

#     mock_event_producer.assert_not_called()
#     mock_notification_event_producer.assert_not_called()


def test_add_host_fail(mq_create_or_update_host, notification_event_producer_mock):
    """
    Test new system notification is not produced after add host fails
    """
    owner_id = "Mike Wazowski"
    host = minimal_host(account=SYSTEM_IDENTITY["account_number"], system_profile={"owner_id": owner_id})

    with pytest.raises(ValidationException):
        mq_create_or_update_host(host, notification_event_producer=notification_event_producer_mock)

    # a host validation error notification should be produced instead
    event = json.loads(notification_event_producer_mock.event)

    assert event is not None
    assert "validation-error" == event["event_type"]


# System Became Stale

# System Deleted

# Host Validation Error