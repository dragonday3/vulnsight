import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

if TYPE_CHECKING:
    from app.models.project import Project


class TargetType(str, enum.Enum):
    IP = "ip"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    CIDR = "cidr"


class Target(Base):
    __tablename__ = "targets"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    value: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(
        Enum(
            TargetType,
            name="target_type",
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
        ),
        nullable=False,
    )
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    authorization_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    # Phase 12 race fix: source -> ISO time of the newest scan of that source
    # whose remediation sync ran. An older scan of the same source is stale
    # and skipped (modules/remediation/sync.py).
    remediation_watermarks: Mapped[dict] = mapped_column(
        JSONB, default=dict, server_default=text("'{}'::jsonb"), nullable=False
    )

    project: Mapped["Project"] = relationship(back_populates="targets")
