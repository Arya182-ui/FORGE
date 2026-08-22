import datetime
import uuid
from sqlalchemy import Column, String, Integer, Float, DateTime, ForeignKey, Text, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from backend.app.config import settings

Base = declarative_base()

class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    target_path = Column(String(512), nullable=False)
    status = Column(String(32), default="PENDING")
    scanned_files_count = Column(Integer, default=0)
    scanned_lines_count = Column(Integer, default=0)
    total_findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    duration_ms = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    rule_id = Column(String(64), nullable=False)
    title = Column(String(256), nullable=False)
    severity = Column(String(32), nullable=False)
    language = Column(String(32), nullable=False)
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=False)
    column_number = Column(Integer, default=0)
    end_line = Column(Integer, default=0)
    code_snippet = Column(Text, default="")
    message = Column(Text, nullable=False)
    confidence = Column(Float, default=1.0)
    owasp_category = Column(String(128), default="Uncategorized")
    recommendation = Column(Text, default="")
    fingerprint = Column(String(64), index=True, nullable=False)
    detection_source = Column(String(64), default="FORGE_CUSTOM_AST")

    scan = relationship("ScanModel", back_populates="findings")


engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)
