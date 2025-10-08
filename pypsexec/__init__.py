# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging

from logging import NullHandler
from typing import Tuple

from .client import Client


logger = logging.getLogger(__name__)
logger.addHandler(NullHandler())


__all__: Tuple[str, ...] = ("Client",)
