# Extending RTX

RTX is designed to be extensible, allowing users and contributors to add support for new package ecosystems or introduce custom trust signals. This document outlines the process for doing so.

## Adding a New Package Scanner

To add support for a new package ecosystem (e.g., a new language's package manager), you'll need to create a new scanner module.

1.  **Create a new scanner file:** In `src/rtx/scanners/`, create a new Python file (e.g., `my_new_scanner.py`).
2.  **Inherit from `BaseScanner`:** Your new scanner class should inherit from `rtx.scanners.base.BaseScanner`.
3.  **Define `manager`, `manifests`, and `ecosystem`:**
    *   `manager`: A unique string identifier for your package manager (e.g., "pip", "cargo").
    *   `manifests`: A list of filenames that identify your package manager's manifest or lock files (e.g., `["requirements.txt", "Pipfile.lock"]`).
    *   `ecosystem`: The ecosystem name used by advisory databases (e.g., "PyPI", "crates.io").
4.  **Implement the `scan` method:** This method takes a `Path` object (the root of the project) and should return a list of `rtx.models.Dependency` objects. This is where your logic for parsing manifest files and extracting dependencies will reside.
5.  **Register your scanner:** In `src/rtx/registry.py`, import your new scanner and add it to the `_SCANNERS` list.

**Example Structure for `src/rtx/scanners/my_new_scanner.py`:**

```python
from __future__ import annotations

from pathlib import Path
from typing import ClassVar

from rtx.models import Dependency
from rtx.scanners.base import BaseScanner

class MyNewScanner(BaseScanner):
    manager: ClassVar[str] = "my-new-manager"
    manifests: ClassVar[list[str]] = ["MyManifest.json", "MyLockfile.lock"]
    ecosystem: ClassVar[str] = "MyEcosystem"

    def scan(self, root: Path) -> list[Dependency]:
        dependencies: list[Dependency] = []
        # Your parsing logic here
        # Example:
        # manifest_path = root / "MyManifest.json"
        # if manifest_path.exists():
        #     # Parse manifest_path and create Dependency objects
        #     dependencies.append(self._dependency(name="my-package", version="1.0.0", manifest=manifest_path))
        return dependencies
```

## Adding a New Trust Signal

Trust signals are used by the `TrustPolicyEngine` to evaluate the trustworthiness of a dependency. To add a new signal:

1.  **Identify the signal logic:** Determine the criteria for your new trust signal (e.g., "package has more than 10 maintainers", "package has a security policy defined").
2.  **Modify `src/rtx/policy.py`:**
    *   In the `TrustPolicyEngine` class, you'll find the `_derive_signals` method. This is where existing signals are computed. Add your new signal's logic here.
    *   Each signal should set a boolean value on the `TrustSignal` object.
    *   Consider creating helper methods within `TrustPolicyEngine` if your signal logic is complex.

**Example of adding a new signal in `_derive_signals`:**

```python
# In src/rtx/policy.py, within TrustPolicyEngine._derive_signals method
# ...
if metadata.maintainer_count() > 10:
    signals.has_many_maintainers = True
# ...
```

## Configuring Existing Trust Policies

Many of RTX's built-in trust policies can be configured via the `rtx.toml` file or environment variables. These settings allow you to fine-tune the thresholds for various trust signals.

To configure a policy, add a `[rtx]` section to your `rtx.toml` file (if it doesn't already exist) and specify the desired parameters:

```toml
[rtx]
# Abandonment policy: number of days without a release before considered abandoned
policy_abandonment_threshold_days = 365

# Churn policy: number of releases in the last 30 days to be considered high or medium churn
policy_churn_high_threshold = 15
policy_churn_medium_threshold = 7

# Bus factor policy: maintainer count thresholds for 'zero' and 'one' maintainer signals
policy_bus_factor_zero_threshold = 1
policy_bus_factor_one_threshold = 2

# Low maturity policy: minimum number of total releases for a package to be considered mature
policy_low_maturity_threshold = 5

# Typosquatting policy: maximum Levenshtein distance for typosquatting detection
policy_typosquat_max_distance = 1
```

Alternatively, you can configure these settings using environment variables, which take precedence over `rtx.toml`. The environment variable names are derived from the `rtx.toml` keys by uppercasing and prefixing with `RTX_` (e.g., `RTX_POLICY_ABANDONMENT_THRESHOLD_DAYS`).

Remember to run tests and ensure your changes integrate well with the existing codebase.
