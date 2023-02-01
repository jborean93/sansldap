# Copyright: (c) 2023, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class SerializationOptions:
    string_encoding: str = "utf-8"
