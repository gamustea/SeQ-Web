
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, Table
)
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()

# Association tables for many-to-many relationships
TargetPort = Table(
    'TargetPort', Base.metadata,
    Column('port_id', Integer, ForeignKey('Port.id'), primary_key=True),
    Column('nmap_scan_id', Integer, ForeignKey('NmapScan.id'), primary_key=True)
)

OpenPort = Table(
    'OpenPort', Base.metadata,
    Column('port_id', Integer, ForeignKey('Port.id'), primary_key=True),
    Column('nmap_scan_id', Integer, ForeignKey('NmapScan.id'), primary_key=True),
    Column('reason', String(255), nullable=False)
)


class Person(Base):
    __tablename__ = 'Person'

    id = Column(Integer, primary_key=True, autoincrement=True)
    first_name = Column(String(64), nullable=False)
    last_name = Column(String(64), nullable=False)
    email = Column(String(128), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)

    user = relationship("User", back_populates="person", uselist=False)


class User(Base):
    __tablename__ = 'User'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False)
    password = Column(String(128), nullable=False)
    person_id = Column(Integer, ForeignKey('Person.id'), nullable=False)

    person = relationship("Person", back_populates="user")
    scans = relationship("Scan", back_populates="user")


class Scan(Base):
    __tablename__ = 'Scan'

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String(255), nullable=False)
    started_at = Column(DateTime, nullable=False)
    user_id = Column(Integer, ForeignKey('User.id'), nullable=False)

    user = relationship("User", back_populates="scans")
    finished_scan = relationship("FinishedScan", uselist=False, back_populates="scan")
    nmap_scan = relationship("NmapScan", uselist=False, back_populates="scan")
    nikto_scan = relationship("NiktoScan", uselist=False, back_populates="scan")
    openvas_scan = relationship("OpenVASScan", uselist=False, back_populates="scan")


class NmapScan(Base):
    __tablename__ = 'NmapScan'

    id = Column(Integer, ForeignKey('Scan.id'), primary_key=True)
    scan = relationship("Scan", back_populates="nmap_scan")

    target_ports = relationship(
        "Port",
        secondary=TargetPort,
        back_populates="target_scans"
    )
    open_ports = relationship(
        "Port",
        secondary=OpenPort,
        back_populates="open_scans"
    )


class FinishedScan(Base):
    __tablename__ = 'FinishedScan'

    id = Column(Integer, ForeignKey('Scan.id'), primary_key=True)
    finished_at = Column(DateTime, nullable=False)

    scan = relationship("Scan", back_populates="finished_scan")


class Port(Base):
    __tablename__ = 'Port'

    id = Column(Integer, primary_key=True, autoincrement=True)
    protocol = Column(String(255), unique=True, nullable=False)

    target_scans = relationship(
        "NmapScan",
        secondary=TargetPort,
        back_populates="target_ports"
    )
    open_scans = relationship(
        "NmapScan",
        secondary=OpenPort,
        back_populates="open_ports"
    )


class NiktoScan(Base):
    __tablename__ = 'NiktoScan'

    id = Column(Integer, ForeignKey('Scan.id'), primary_key=True)

    scan = relationship("Scan", back_populates="nikto_scan")
    incidents = relationship("NiktoIncident", secondary='ScanIncident', back_populates="scans")


class NiktoIncident(Base):
    __tablename__ = 'NiktoIncident'

    id = Column(Integer, primary_key=True, autoincrement=True)
    nikto_scan_id = Column(Integer, ForeignKey('NiktoScan.id'), nullable=False)

    scans = relationship("NiktoScan", secondary='ScanIncident', back_populates="incidents")


class ScanIncident(Base):
    __tablename__ = 'ScanIncident'

    nikto_scan_id = Column(Integer, ForeignKey('NiktoScan.id'), primary_key=True)
    nikto_incident_id = Column(Integer, ForeignKey('NiktoIncident.id'), primary_key=True)


class OpenVASScan(Base):
    __tablename__ = 'OpenVASScan'

    id = Column(Integer, ForeignKey('Scan.id'), primary_key=True)

    scan = relationship("Scan", back_populates="openvas_scan")
