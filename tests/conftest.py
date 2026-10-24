import pytest

from agentshield.hitl import AllowAllApprover, DenyAllApprover
from agentshield.shield import Shield


@pytest.fixture
def shield() -> Shield:
    return Shield.default(approver=DenyAllApprover())


@pytest.fixture
def permissive_shield() -> Shield:
    return Shield.default(approver=AllowAllApprover())
