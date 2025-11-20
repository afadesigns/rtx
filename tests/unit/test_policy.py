from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime
from unittest.mock import MagicMock

import pytest

from rtx.metadata import ReleaseMetadata
from rtx.models import Advisory, Dependency, Severity
from rtx.policy import TrustPolicyEngine, levenshtein
from rtx.utils import utc_now
