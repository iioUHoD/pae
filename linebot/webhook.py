
"""linebot.http_client webhook."""

from __future__ import unicode_literals

import base64
import hashlib
import hmac
import inspect
import json

from .exceptions import InvalidSignatureError
from .models.events import (
    MessageEvent,
    FollowEvent,
    UnfollowEvent,
    JoinEvent,
    LeaveEvent,
    PostbackEvent,
    BeaconEvent,
    AccountLinkEvent,
)
from .utils import LOGGER, PY3, safe_compare_digest


if hasattr(hmac, "compare_digest"):
    def compare_digest(val1, val2):

        return hmac.compare_digest(val1, val2)
else:
    def compare_digest(val1, val2):
rn safe_compare_digest(val1, val2)


class SignatureValidator(object):


    def __init__(self, channel_secret):
        self.channel_secret = channel_secret.encode('utf-8')

    def validate(self, body, signature):
        gen_signature = hmac.new(
            self.channel_secret,
            body.encode('utf-8'),
            hashlib.sha256
        ).digest()

        return compare_digest(
                signature.encode('utf-8'), base64.b64encode(gen_signature)
        )


class WebhookParser(object):
    """Webhook Parser."""

    def __init__(self, channel_secret):

        self.signature_validator = SignatureValidator(channel_secret)

    def parse(self, body, signature):

        if not self.signature_validator.validate(body, signature):
            raise InvalidSignatureError(
                'Invalid signature. signature=' + signature)

        body_json = json.loads(body)
        events = []
        for event in body_json['events']:
            event_type = event['type']
            if event_type == 'message':
                events.append(MessageEvent.new_from_json_dict(event))
            elif event_type == 'follow':
                events.append(FollowEvent.new_from_json_dict(event))
            elif event_type == 'unfollow':
                events.append(UnfollowEvent.new_from_json_dict(event))
            elif event_type == 'join':
                events.append(JoinEvent.new_from_json_dict(event))
            elif event_type == 'leave':
                events.append(LeaveEvent.new_from_json_dict(event))
            elif event_type == 'postback':
                events.append(PostbackEvent.new_from_json_dict(event))
            elif event_type == 'beacon':
                events.append(BeaconEvent.new_from_json_dict(event))
            elif event_type == 'accountLink':
                events.append(AccountLinkEvent.new_from_json_dict(event))
            else:
                LOGGER.warn('Unknown event type. type=' + event_type)

        return events


class WebhookHandler(object):
    """Webhook Handler."""

    def __init__(self, channel_secret):
        """__init__ method.

        :param str channel_secret: Channel secret (as text)
        """
        self.parser = WebhookParser(channel_secret)
        self._handlers = {}
        self._default = None

    def add(self, event, message=None):
        def decorator(func):
            if isinstance(message, (list, tuple)):
                for it in message:
                    self.__add_handler(func, event, message=it)
            else:
                self.__add_handler(func, event, message=message)

            return func

        return decorator

    def default(self):
        def decorator(func):
            self._default = func
            return func

        return decorator

    def handle(self, body, signature):
      
        events = self.parser.parse(body, signature)

        for event in events:
            func = None
            key = None

            if isinstance(event, MessageEvent):
                key = self.__get_handler_key(
                    event.__class__, event.message.__class__)
                func = self._handlers.get(key, None)

            if func is None:
                key = self.__get_handler_key(event.__class__)
                func = self._handlers.get(key, None)

            if func is None:
                func = self._default

            if func is None:
                LOGGER.info('No handler of ' + key + ' and no default handler')
            else:
                args_count = self.__get_args_count(func)
                if args_count == 0:
                    func()
                else:
                    func(event)

    def __add_handler(self, func, event, message=None):
        key = self.__get_handler_key(event, message=message)
        self._handlers[key] = func

    @staticmethod
    def __get_args_count(func):
        if PY3:
            arg_spec = inspect.getfullargspec(func)
            return len(arg_spec.args)
        else:
            arg_spec = inspect.getargspec(func)
            return len(arg_spec.args)

    @staticmethod
    def __get_handler_key(event, message=None):
        if message is None:
            return event.__name__
        else:
            return event.__name__ + '_' + message.__name__
