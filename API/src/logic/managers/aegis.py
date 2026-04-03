import json
import os
import random
import re
import threading
from datetime import datetime, date
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.orm import Session

from src.logic.documents import (
    AegisAIWriter,
    AegisAlertFetcher,
    AegisAlert,
    AegisContent,
)
from src.core.model import (
    AegisDocument,
    AegisDocumentAlert,
    AegisPill,
    AegisTip,
    Topic,
    User,
)
from src.misc.configread import ConfigReader
from src.misc.logging import SecOpsLogger

from ._base import BaseManager


class AegisManager(BaseManager):

    _FALLBACK_BRANDS: list[str] = [
        "Microsoft", "Google", "Cisco", "Apple", "Adobe",
        "Oracle", "SAP", "VMware", "Fortinet", "Palo Alto",
        "Juniper", "IBM", "Linux", "Android", "Chrome",
    ]

    def __init__(self, user: User, session=None):
        super().__init__(session)
        self.user = user
        self.config_reader = ConfigReader()
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()
        self.alert_fetcher = AegisAlertFetcher(
            logger=self.logger,
            fallback_brands=self._FALLBACK_BRANDS,
        )

    def _read_cfg(self) -> dict[str, Any]:
        aegis    = self.config_reader.get_aegis_config()
        ol       = aegis.get("ollama", {}) or {}
        paths    = aegis.get("paths",  {}) or {}
        api_root = Path(__file__).resolve().parents[3]

        stack_dir  = api_root / str(paths.get("stackDir",  "data/aegis/stack"))
        output_dir = api_root / str(paths.get("outputDir", "data/aegis/output"))
        output_dir.mkdir(parents=True, exist_ok=True)

        return {
            "enabled":         bool(aegis.get("enabled", True)),
            "ollama_host":     str(ol.get("host",           "http://localhost:11434")),
            "ollama_model":    str(ol.get("model",          "mistral")),
            "timeout_seconds": int(ol.get("timeoutSeconds", 120)),
            "stack_dir":       stack_dir,
            "output_dir":      output_dir,
        }

    def _get_topic_from_db(self, topic_id: Optional[int]) -> tuple:
        if topic_id is not None:
            topic = self.session.query(Topic).filter(Topic.id == topic_id).first()
            if topic:
                return topic, False
            self.logger.warning(f"Topic id={topic_id} no encontrado. Se usará uno aleatorio.")

        all_topics = self.session.query(Topic).all()
        if not all_topics:
            return None, False
        return random.choice(all_topics), True

    def _load_reference_stack(self, stack_dir: Path) -> str:
        if not stack_dir.exists():
            return ""
        files = sorted(stack_dir.glob("*.md"), key=lambda p: p.stat().st_mtime)
        if not files:
            return ""
        return "\n\n---\n\n".join(p.read_text(encoding="utf-8") for p in files[-3:])

    def _create_pending_document(self, topic_id: int) -> int:
        ts          = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        placeholder = f"pending_{ts}_{self.user.id}_{topic_id}"

        doc = AegisDocument(
            title=placeholder[:64],
            filename=f"{placeholder}.json"[:128],
            status="pending",
            format="json",
            topic_id=topic_id,
            user_id=self.user.id,
        )
        self.session.add(doc)
        self.session.flush()
        self._safe_commit()
        return doc.id

    def _update_document(
        self,
        document_id: int,
        status: str,
        title: str | None = None,
        filename: str | None = None,
        error: str | None = None,
    ) -> None:
        doc = self.session.get(AegisDocument, document_id)
        if not doc:
            self.logger.error(f"_update_document: doc {document_id} no encontrado")
            return
        doc.status = status
        if title:
            doc.title = title[:64]
        if filename:
            doc.filename = filename[:128]
        if error and status == "error":
            error_title = f"[ERR{document_id}] {error}"
            doc.title = error_title[:64]
        self._safe_commit()

    def _persist_pill(
        self,
        document_id: int,
        content: AegisContent,
    ) -> None:
        """Guarda AegisPill + AegisTip en BD."""
        existing = self.session.get(AegisPill, document_id)
        if existing:
            self.session.delete(existing)
            self.session.flush()

        pill = AegisPill(
            id=document_id,
            subtitle=content.subtitle,
            intro=content.intro,
            closing=content.closing,
            contact_email=content.contact_email or None,
        )
        self.session.add(pill)
        self.session.flush()

        for i, tip_data in enumerate(content.tips, start=1):
            tip = AegisTip(
                pill_id=pill.id,
                position=i,
                headline=tip_data.headline,
                body=tip_data.body,
                links_json=tip_data.links or None,
            )
            self.session.add(tip)

        self.session.flush()
        self.logger.info(
            f"AegisPill {document_id} persistida con {len(content.tips)} tips"
        )

    def _persist_alerts(
        self,
        document_id: int,
        alerts: list[AegisAlert],
    ) -> None:
        """Guarda AegisDocumentAlert en BD."""
        (
            self.session.query(AegisDocumentAlert)
            .filter(AegisDocumentAlert.document_id == document_id)
            .delete()
        )
        self.session.flush()

        for i, alert in enumerate(alerts, start=1):
            pub_date = None
            if alert.published:
                try:
                    pub_date = date.fromisoformat(alert.published[:10])
                except ValueError:
                    pass

            db_alert = AegisDocumentAlert(
                document_id=document_id,
                position=i,
                source=alert.source,
                source_label="INCIBE-CERT" if alert.source == "incibe" else "NVD/CVE",
                title=alert.title[:256],
                published=pub_date,
                severity=alert.severity or None,
                affected_brands=alert.brands or None,
                description=(alert.description or "")[:500] or None,
                url=alert.url[:512],
            )
            self.session.add(db_alert)

        self.session.flush()
        self.logger.info(
            f"AegisDocumentAlert: {len(alerts)} alertas persistidas para doc {document_id}"
        )

    def _generate_content(
        self,
        topic_id: Optional[int],
        tweaks: dict[str, Any],
        cfg: dict[str, Any],
    ) -> AegisContent:
        if not cfg["enabled"]:
            raise RuntimeError("Aegis está deshabilitado por configuración")

        topic, was_random = self._get_topic_from_db(topic_id)

        if topic is None:
            topic_note = "No hay topics en BD. Contenido genérico generado."
            resolved_topic_id = topic_id or 0
            topic_title = tweaks.get("topicFocus") or "Ciberseguridad general"
        elif was_random:
            topic_note = (
                f"Topic solicitado no encontrado. "
                f"Se usó uno aleatorio: '{topic.title}' (id={topic.id})."
            )
            resolved_topic_id = topic.id
            topic_title = topic.title
        else:
            topic_note = ""
            resolved_topic_id = topic.id
            topic_title = topic.title

        if topic_note:
            self.logger.info(f"Aegis topic note: {topic_note}")

        reference = self._load_reference_stack(cfg["stack_dir"])

        writer = AegisAIWriter(
            host=cfg["ollama_host"],
            model=cfg["ollama_model"],
            logger=self.logger,
        )

        return writer.generate_pill(
            topic=topic,
            resolved_topic_id=resolved_topic_id,
            topic_title=topic_title,
            topic_note=topic_note,
            reference=reference,
            tweaks=tweaks,
        )

    def _run_generate(self, document_id: int, topic_id: int, tweaks: dict) -> None:
        """
        Ejecutado en un thread daemon.
        Orquesta: generar → parsear → validar → persistir en BD → escribir .json.
        """
        try:
            cfg     = self._read_cfg()
            content = self._generate_content(topic_id, tweaks, cfg)

            alerts = self.alert_fetcher.fetch_alerts(
                brands=tweaks.get("associatedBrands", []),
                max_per_brand=2,
                timeout=10,
            )

            self._persist_pill(document_id, content)
            self._persist_alerts(document_id, alerts)

            ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{ts}_{self.user.id}_{topic_id}.json"
            path     = cfg["output_dir"] / filename

            full_dict = content.to_json_dict(document_id, alerts)
            with path.open("w", encoding="utf-8") as f:
                json.dump(full_dict, f, ensure_ascii=False, indent=2)

            self._update_document(
                document_id=document_id,
                status="done",
                title=content.subtitle,
                filename=filename,
            )
            self.logger.info(
                f"Aegis: '{filename}' generado y persistido (id={document_id})"
            )

        except Exception as e:
            self.logger.error(
                f"Aegis _run_generate: error en doc {document_id}: {e}",
                exc_info=True,
            )
            try:
                self._update_document(
                    document_id=document_id,
                    status="error",
                    error=str(e)[:60],
                )
            except Exception as update_err:
                self.logger.error(
                    f"Aegis: no se pudo actualizar estado de error: {update_err}"
                )
        finally:
            self.close_session()

    def generate(self, topic_id: int, tweaks: Optional[dict] = None) -> int:
        """Lanza la generación asíncrona. Devuelve el documentId."""
        tweaks      = tweaks or {}
        document_id = self._create_pending_document(topic_id)

        thread_manager = self.__class__(self.user)
        thread = threading.Thread(
            target=thread_manager._run_generate,
            args=(document_id, topic_id, tweaks),
            daemon=True,
            name=f"Aegis-{document_id}",
        )
        thread.start()
        return document_id

    def get_document(self, document_id: int) -> dict | None:
        """
        Devuelve el estado y contenido de un documento.

        Para documentos 'done', incluye la estructura completa desde BD
        (no lee el fichero, los datos ya están en las tablas relacionales).
        """
        doc = self.session.get(AegisDocument, document_id)
        if not doc:
            return None

        result = {
            "id":          doc.id,
            "title":       doc.title,
            "filename":    doc.filename,
            "status":      doc.status,
            "format":      doc.format,
            "generatedAt": doc.generated_at.isoformat(),
            "topicId":     doc.topic_id,
            "userId":      doc.user_id,
            "pill":        None,
            "alerts":      [],
        }

        if doc.status == "done" and doc.pill:
            result["pill"]   = doc.pill.to_dict()
            result["alerts"] = [a.to_dict() for a in doc.alerts]

        return result

    def get_document_path(self, document_id: int) -> Path:
        """Devuelve la ruta del fichero generado (para descarga directa)."""
        doc = (
            self.session.query(AegisDocument)
            .filter(
                AegisDocument.id      == document_id,
                AegisDocument.user_id == self.user.id,
            )
            .first()
        )
        if not doc:
            raise ValueError(
                f"Documento {document_id} no encontrado o no pertenece al usuario"
            )
        cfg  = self._read_cfg()
        path = cfg["output_dir"] / doc.filename
        if not path.exists():
            raise FileNotFoundError(
                f"El fichero '{doc.filename}' no existe en disco."
            )
        return path

    def delete_document(self, document_id: int) -> None:
        doc = (
            self.session.query(AegisDocument)
            .filter(
                AegisDocument.id      == document_id,
                AegisDocument.user_id == self.user.id,
            )
            .first()
        )
        if not doc:
            raise ValueError(
                f"Documento {document_id} no encontrado o no pertenece al usuario"
            )
        cfg  = self._read_cfg()
        path = cfg["output_dir"] / doc.filename
        if path.exists():
            os.remove(path)
            self.logger.info(f"Aegis: fichero eliminado → {path}")

        self.session.delete(doc)
        self.session.commit()
        self.logger.info(f"Aegis: documento id={document_id} eliminado de BD")

    def list_documents(self) -> list[dict]:
        docs = (
            self.session.query(AegisDocument)
            .filter(AegisDocument.user_id == self.user.id)
            .order_by(AegisDocument.generated_at.desc())
            .all()
        )
        return [
            {
                "id":          d.id,
                "title":       d.title,
                "filename":    d.filename,
                "format":      d.format,
                "status":      d.status,
                "generatedAt": d.generated_at.isoformat(),
                "topicId":     d.topic_id,
            }
            for d in docs
        ]

    def get_topics(self) -> list[dict]:
        topics = self.session.query(Topic).order_by(Topic.title).all()
        return [
            {
                "id":          t.id,
                "title":       t.title,
            }
            for t in topics
        ]


