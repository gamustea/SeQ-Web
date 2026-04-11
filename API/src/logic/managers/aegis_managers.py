"""
aegis_managers.py
─────────────────
Manager de operaciones Aegis.

Responsabilidades:
    — Crear documentos pendientes y lanzar el workflow de generación en thread
    — Persistir AegisContent (tips directamente en AegisTip con FK a AegisDocument)
    — Persistir AegisAlert en AegisDocumentAlert
    — Exponer get_document, list_documents, delete_document, get_document_path y get_topics
"""

from __future__ import annotations

import json
import os
import random
import threading
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.core.model import AegisDocument, AegisDocumentAlert, AegisTip, Topic, User
from src.logic.documents.aegis_pills import (
    AegisAlert,
    AegisAlertFetcher,
    AegisAIWriter,
    AegisContent,
    AlertSource,
)
from src.misc import ConfigReader, SecOpsLogger
from ._base import BaseManager


class AegisManager(BaseManager):
    """
    Gestiona el ciclo de vida completo de los documentos Aegis:
    creación, generación asíncrona, consulta, exportación y eliminación.
    """

    _lock = threading.Lock()

    def __init__(self, user: User, session: Session = None) -> None:
        super().__init__(session)
        self.user = user
        self.logger       = SecOpsLogger(f"AegisManager[{user.id}]").get_logger()
        self.alert_fetcher = AegisAlertFetcher(logger=self.logger)

    # =========================================================================
    # API PÚBLICA
    # =========================================================================

    def generate(self, topic_id: int, tweaks: dict | None = None) -> int:
        """
        Lanza la generación asíncrona de una píldora y devuelve el documentId
        inmediatamente. Thread-safe.
        """
        with self._lock:
            tweaks      = tweaks or {}
            document_id = self._create_pending_document(topic_id)

            thread_manager = self.__class__(self.user)
            threading.Thread(
                target  = thread_manager._run_generation_workflow,
                args    = (document_id, topic_id, tweaks),
                daemon  = True,
                name    = f"AegisGen-{document_id}",
            ).start()

        return document_id

    def get_document(self, doc_id: int) -> dict | None:
        doc = self.session.query(AegisDocument).filter(AegisDocument.id == doc_id).first()
        if not doc:
            return None
        
        return {
            "id": doc.id,
            "internalName": doc.title,           # Identificador técnico (pending_xxx)
            "title": doc.subtitle or "Sin título",  # TÍTULO REAL DE LA PÍLDORA (lo que ve el usuario)
            "userId": doc.user.id,
            "topicId": doc.topic_id,
            "topicTitle": doc.topic.title if doc.topic else "Tema desconocido",  # Categoría
            "status": doc.status,
            "pill": {
                "subtitle": doc.subtitle,        # Redundante pero explícito
                "intro": doc.intro,
                "closing": doc.closing,
                "company": doc.company,
                "contactEmail": doc.contact_email,
                "tips": [t.to_dict() for t in doc.tips],
            },
            "alerts": [a.to_dict() for a in doc.alerts],
            "generatedAt": doc.generated_at.isoformat() if doc.generated_at else None,
        }

        if doc.status == "done":
            result["pill"]   = doc.pill_to_dict()
            result["alerts"] = [a.to_dict() for a in sorted(doc.alerts, key=lambda a: a.position)]

        return result

    def get_document_path(self, document_id: int) -> Path:
        """Devuelve la ruta al archivo generado, validando propiedad y existencia."""
        doc = (
            self.session.query(AegisDocument)
            .filter(AegisDocument.id == document_id, AegisDocument.user_id == self.user.id)
            .first()
        )
        if not doc:
            raise ValueError(f"Documento {document_id} no existe o no pertenece al usuario")

        path = self._read_cfg()["output_dir"] / doc.filename
        if not path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {doc.filename}")

        return path

    def delete_document(self, document_id: int) -> None:
        """Elimina el documento de BD y el archivo en disco de forma atómica."""
        doc = (
            self.session.query(AegisDocument)
            .filter(AegisDocument.id == document_id, AegisDocument.user_id == self.user.id)
            .first()
        )
        if not doc:
            raise ValueError(f"Documento {document_id} no existe o no pertenece al usuario")

        path = self._read_cfg()["output_dir"] / doc.filename
        try:
            if path.exists():
                os.remove(path)
                self.logger.info(f"Archivo eliminado: {path}")
            self.session.delete(doc)
            self.session.commit()
            self.logger.info(f"Documento {document_id} eliminado de BD")
        except Exception as exc:
            self.session.rollback()
            raise RuntimeError(f"Error eliminando documento: {exc}")

    def list_documents(self) -> list[dict]:
        """Lista todos los documentos del usuario, ordenados por fecha descendente."""
        docs = (
            self.session.query(AegisDocument)
            .filter(AegisDocument.user_id == self.user.id)
            .order_by(AegisDocument.generated_at.desc())
            .limit(100)
            .all()
        )
        return [
            {
                "id":          d.id,
                "title":       d.title,
                "filename":    d.filename,
                "format":      d.format,
                "status":      d.status,
                "generatedAt": d.generated_at.isoformat() if d.generated_at else None,
                "topicId":     d.topic_id,
            }
            for d in docs
        ]

    def get_topics(self) -> list[dict]:
        """Devuelve todos los temas disponibles ordenados por título."""
        return [
            {"id": t.id, "title": t.title}
            for t in self.session.query(Topic).order_by(Topic.title).all()
        ]

    # =========================================================================
    # WORKFLOW DE GENERACIÓN (privado)
    # =========================================================================

    def _run_generation_workflow(
        self,
        document_id: int,
        topic_id:    int,
        tweaks:      dict[str, Any],
    ) -> None:
        """Orquesta todos los pasos de generación en el thread secundario."""
        cfg = self._read_cfg()

        if not cfg["enabled"]:
            raise RuntimeError("Aegis deshabilitado en configuración")

        # El campo company es el único requerido en tweaks
        if not tweaks.get("company"):
            raise ValueError("El campo 'company' es obligatorio en tweaks")

        try:
            # 1. Resolución de topic
            topic, was_random = self._get_topic_from_db(topic_id)
            if topic is None:
                topic_note     = "No hay topics en BD. Contenido genérico."
                resolved_id    = topic_id or 0
                resolved_title = tweaks.get("topicFocus", "Ciberseguridad General")
            elif was_random:
                topic_note     = f"Topic {topic_id} no encontrado. Usado: '{topic.title}'"
                resolved_id    = topic.id
                resolved_title = topic.title
            else:
                topic_note     = ""
                resolved_id    = topic.id
                resolved_title = topic.title

            # 2. Carga de referencias de disco
            reference = self._load_reference_stack(cfg["stack_dir"])

            # 3. Generación de contenido con el modelo
            writer = AegisAIWriter()
            content: AegisContent = writer.generate(
                topic             = topic,
                resolved_topic_id = resolved_id,
                topic_title       = resolved_title,
                topic_note        = topic_note,
                reference         = reference,
                tweaks            = tweaks,
            )

            # 4. Fetch de alertas
            alerts = self.alert_fetcher.fetch_alerts(
                brands        = tweaks.get("associatedBrands", []),
                max_per_brand = 2,
            )

            # 5. Persistencia
            self._persist_content_atomic(document_id, content)
            self._persist_alerts_atomic(document_id, alerts)

            # 6. Escritura del archivo de archivo
            ts       = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{ts}_{self.user.id}_{resolved_id}.json"
            filepath = cfg["output_dir"] / filename

            with open(filepath, "w", encoding="utf-8") as fh:
                json.dump(content.to_json_dict(document_id, alerts), fh, ensure_ascii=False, indent=2)

            # 7. Actualización del estado a 'done'
            self._update_document_status(
                document_id = document_id,
                status      = "done",
                title       = content.subtitle,
                filename    = filename,
            )
            self.logger.info(f"Documento {document_id} generado: {filename}")

        except Exception as exc:
            self.logger.error(f"Error en workflow {document_id}: {exc}", exc_info=True)
            self._update_document_status(
                document_id = document_id,
                status      = "error",
                error       = str(exc)[:100],
            )
        finally:
            self.close_session()

    # =========================================================================
    # PERSISTENCIA (privado)
    # =========================================================================

    def _persist_content_atomic(self, document_id: int, content: AegisContent) -> None:
        """
        Persiste el contenido de la píldora directamente en AegisDocument
        y los tips en AegisTip. Elimina tips previos si los hubiera.
        """
        try:
            doc = self.session.get(AegisDocument, document_id)
            if not doc:
                raise ValueError(f"Documento {document_id} no encontrado para persistir")

            # Volcado de campos de píldora sobre el documento
            doc.subtitle      = content.subtitle
            doc.intro         = content.intro
            doc.closing       = content.closing
            doc.contact_email = content.contact_email or None
            doc.company       = content.company

            # Eliminación de tips previos
            self.session.query(AegisTip).filter(AegisTip.document_id == document_id).delete()
            self.session.flush()

            for i, tip in enumerate(content.tips, 1):
                self.session.add(AegisTip(
                    document_id = document_id,
                    position    = i,
                    headline    = tip.headline,
                    body        = tip.body,
                    links_json  = tip.links or None,
                ))

            self._safe_commit()
            self.logger.info(f"Contenido persistido para doc {document_id}: {len(content.tips)} tips")

        except Exception as exc:
            self.session.rollback()
            raise RuntimeError(f"Error persistiendo contenido: {exc}")

    def _persist_alerts_atomic(self, document_id: int, alerts: list[AegisAlert]) -> None:
        """Persiste alertas con batch insert, eliminando las previas."""
        try:
            self.session.query(AegisDocumentAlert).filter(
                AegisDocumentAlert.document_id == document_id
            ).delete()
            self.session.flush()

            for i, alert in enumerate(alerts, 1):
                pub_date: date | None = None
                if alert.published:
                    try:
                        pub_date = date.fromisoformat(alert.published[:10])
                    except ValueError:
                        pass

                self.session.add(AegisDocumentAlert(
                    document_id     = document_id,
                    position        = i,
                    source          = alert.source.value,
                    source_label    = "INCIBE-CERT" if alert.source == AlertSource.INCIBE else "NVD/CVE",
                    title           = alert.title[:256],
                    published       = pub_date,
                    severity        = alert.severity.value if isinstance(alert.severity, Enum) else alert.severity,
                    affected_brands = alert.brands or None,
                    description     = alert.description[:500] if alert.description else None,
                    url             = alert.url[:512],
                ))

            self._safe_commit()
            self.logger.info(f"Alertas persistidas para doc {document_id}: {len(alerts)}")

        except Exception as exc:
            self.session.rollback()
            raise RuntimeError(f"Error persistiendo alertas: {exc}")

    # =========================================================================
    # HELPERS (privado)
    # =========================================================================

    def _read_cfg(self) -> dict:
        aegis = ConfigReader().get_aegis_config() or {}
        ol = aegis.get("ollama", {}) or {}
        paths = aegis.get("paths", {}) or {}
        
        api_root = Path(__file__).resolve().parents[3]
        stack_dir = api_root / str(paths.get("stackDir", "data/aegis/stack"))
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

    def _get_topic_from_db(self, topic_id: int | None) -> tuple[Topic | None, bool]:
        """Devuelve (topic, was_random). Si topic_id no existe, elige uno aleatorio."""
        if topic_id is not None:
            topic = self.session.query(Topic).filter(Topic.id == topic_id).first()
            if topic:
                return topic, False
            self.logger.warning(f"Topic {topic_id} no encontrado, usando aleatorio")

        all_topics = self.session.query(Topic).all()
        if not all_topics:
            return None, False

        return random.choice(all_topics), True

    def _load_reference_stack(self, stack_dir: Path) -> str:
        """Carga los 3 archivos .md más recientes del directorio de referencias."""
        if not stack_dir.exists():
            return ""

        files = sorted(stack_dir.glob("*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
        contents = []
        for f in files[:3]:
            try:
                content = f.read_text(encoding="utf-8")
                if len(content) > 50_000:
                    content = content[:50_000] + "\n... [truncado]"
                contents.append(content)
            except Exception as exc:
                self.logger.warning(f"No se pudo leer {f}: {exc}")

        return "\n\n---\n\n".join(contents)

    def _create_pending_document(self, topic_id: int) -> int:
        """Crea un registro AegisDocument en estado 'pending' y devuelve su ID."""
        ts          = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        placeholder = f"pending_{ts}_{self.user.id}_{topic_id}"

        doc = AegisDocument(
            title    = placeholder[:64],
            filename = f"{placeholder}.json"[:128],
            status   = "pending",
            format   = "json",
            topic_id = topic_id,
            user_id  = self.user.id,
        )
        self.session.add(doc)
        self._safe_commit()
        return doc.id

    def _update_document_status(
        self,
        document_id: int,
        status:      str,
        title:       str | None = None,
        filename:    str | None = None,
        error:       str | None = None,
    ) -> None:
        """Actualiza el estado del documento, con manejo explícito de errores de BD."""
        try:
            doc = self.session.get(AegisDocument, document_id)
            if not doc:
                self.logger.error(f"Documento {document_id} no encontrado para actualizar estado")
                return

            doc.status = status
            if title:
                doc.title = title[:64]
            if filename:
                doc.filename = filename[:128]
            if error and status == "error":
                doc.title = f"[ERR{document_id}] {error[:50]}"[:64]

            self._safe_commit()
        except Exception as exc:
            self.logger.error(f"Error actualizando estado de doc {document_id}: {exc}")
            self.session.rollback()