from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator

SUPPORTED_PROFILE = "ga5-incident-agent/v2"


class IncidentPayload(BaseModel):
    incidentId: str
    title: str
    service: str
    severity: str
    transcript: str
    allowedRootCauses: list[str]


class PolicyPayload(BaseModel):
    maximumDiagnostics: int = 3
    effectTools: list[str] = Field(default_factory=list)
    approvalRequiredFor: list[str] = Field(default_factory=list)
    doNotExport: list[str] = Field(default_factory=list)


class ToolSpec(BaseModel):
    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=dict)


class IncidentRequest(BaseModel):
    profile: str
    runId: str
    agentName: str
    publicMarker: str
    sensitive: dict[str, Any] = Field(default_factory=dict)
    incident: IncidentPayload
    toolCatalog: list[ToolSpec]
    policy: PolicyPayload

    @field_validator("runId", "agentName", "publicMarker")
    @classmethod
    def _nonempty(cls, v: str) -> str:
        if not v or not isinstance(v, str):
            raise ValueError("must be a nonempty string")
        return v


class ReceiptOutcome(BaseModel):
    actionId: str
    callId: str
    attempt: int
    status: int
    resultClass: Optional[str] = None
    errorType: Optional[str] = None
    nonce: str


class ReceiptApproval(BaseModel):
    approvalId: str
    decision: str  # "approved" | "rejected"
    nonce: str


class ReceiptRequest(BaseModel):
    receiptId: str
    outcomes: list[ReceiptOutcome] = Field(default_factory=list)
    approvals: list[ReceiptApproval] = Field(default_factory=list)
