"""
aegis_managers.py
─────────────────
Manager de operaciones Aegis.

Responsabilidades:
    — Crear documentos pendientes y lanzar el workflow de generación en thread
    — Persistir AegisContent (tips directamente en AegisTip con FK a AegisDocument)
    — Persistir AegisAlert en AegisDocumentAlert
    — Exponer get_document, list_user_documents, delete_document, get_document_path y get_topics
"""

from __future__ import annotations

import json
import logging
import random
import threading
from datetime import date, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from src.modules.aegis.exceptions import DocumentError
import src.modules.system.config_reading as CR
from src.modules.users import User
from src.modules.system.taskqueue import ITaskQueue, TaskQueue, job_context
from src.modules.infrastructure import UnitOfWork
from src.modules.infrastructure.session import get_db_session
from src.modules.shared._documents import (
    get_document_by_id,
    delete_document_file,
    update_document_status,
    serialize_document_list,
)

from .model import AegisDocument, Topic
from .services import AegisAIWriter, AegisAlertFetcher, AlertSource, AegisAlert, AegisContent
from .repositories import AegisDocumentRepository


logger = logging.getLogger(__name__)


class AegisManager:
    """
    Gestiona el ciclo de vida completo de los documentos Aegis:
    creación, generación asíncrona, consulta, exportación y eliminación.

    Toda la persistencia se realiza a través de AegisDocumentRepository
    usando UnitOfWork. El manager no gestiona sesiones directamente.
    """

    _lock = threading.Lock()

    def __init__(self, user: User, task_queue: ITaskQueue | None = None) -> None:
        self.user = user
        self.alert_fetcher = AegisAlertFetcher()
        self._tq: ITaskQueue = task_queue or TaskQueue.get_instance()

    # =========================================================================
    # API PÚBLICA
    # =========================================================================

    def generate(self, topic_id: int, tweaks: dict | None = None) -> int:
        """
        Lanza la generacion asincrona de una pildora y devuelve el documentId
        inmediatamente. Thread-safe.
        """
        with self._lock:
            tweaks      = tweaks or {}
            document_id = self._create_pending_document(topic_id)

            self._tq.submit(
                func=AegisManager.execute_aegis_generation,
                args=(document_id, topic_id, tweaks, self.user.id),
                name=f"AegisGen-{document_id}",
                category="aegis.generate",
                external_id=f"aegis-doc:{document_id}",
            )

        return document_id

    def get_document(self, doc_id: int) -> dict | None:
        session = get_db_session()
        repo = AegisDocumentRepository(session=session)
        doc = repo.get_by_id(doc_id)
        if not doc:
            return None

        result = {
            "id": doc.id,
            "internalName": doc.title,
            "title": doc.subtitle or "Sin título",
            "userId": doc.user.id,
            "topicId": doc.topic_id,
            "topicTitle": doc.topic.title if doc.topic else "Tema desconocido",
            "status": doc.status,
            "pill": {
                "subtitle": doc.subtitle,
                "intro": doc.intro,
                "closing": doc.closing,
                "company": doc.company,
                "contactEmail": doc.contact_email,
                "tips": [t.to_dict() for t in doc.tips],
            },
            "alerts": [a.to_dict() for a in doc.alerts],
            "generatedAt": doc.generated_at.isoformat() if doc.generated_at else None, # type: ignore
        }

        if doc.status == "done": # type: ignore
            result["pill"] = doc.pill_to_dict()
            result["alerts"] = [a.to_dict() for a in sorted(doc.alerts, key=lambda a: a.position)]

        return result

    def update_pill(self, doc_id: int, pill: dict) -> dict:
        """
        Reemplaza el contenido editable de una píldora ya generada (upsert).

        Persiste subtitle, intro, closing, contactEmail, company y la lista de
        tips. Las alertas permanecen inmutables. Mantiene sincronizado el
        'title' interno (etiqueta del historial) con el nuevo subtitle y
        regenera el JSON de archivo en disco para que /download no quede
        desincronizado con /document y /export.

        Args:
            doc_id: ID del documento a actualizar (debe existir y ser del usuario).
            pill: Diccionario validado con subtitle, intro, closing,
                  contactEmail, company y tips.

        Returns:
            El documento actualizado (mismo formato que get_document).
        """
        subtitle = pill["subtitle"]
        intro = pill.get("intro", "") or None
        closing = pill.get("closing", "") or None
        contact_email = pill.get("contactEmail", "") or None
        company = pill.get("company", "") or None

        tips_data = [
            {
                "headline": tip["headline"],
                "body": tip["body"],
                "links": (
                    [{"text": lk["text"], "url": lk["url"]} for lk in tip.get("links") or []]
                    or None
                ),
            }
            for tip in pill.get("tips", [])
        ]

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            doc = repo.update_content_fields(
                doc_id=doc_id,
                subtitle=subtitle,
                intro=intro,
                closing=closing,
                contact_email=contact_email,
                company=company,
            )
            if doc is not None:
                # Mantener sincronizada la etiqueta del historial (title interno).
                doc.title = subtitle[:64]
            repo.save_tips(doc_id, tips_data)
            logger.info(f"Píldora {doc_id} actualizada: {len(tips_data)} tips")

        self._rewrite_archive_file(doc_id, subtitle, intro, closing, contact_email, tips_data)

        return self.get_document(doc_id)

    def _rewrite_archive_file(
        self,
        doc_id: int,
        subtitle: str | None,
        intro: str | None,
        closing: str | None,
        contact_email: str | None,
        tips_data: list[dict],
    ) -> None:
        """
        Reescribe el subárbol 'pill' del JSON de archivo en disco conservando
        metadata y alerts. Si el fichero no existe, registra warning y continúa
        (la BD es la fuente de verdad).
        """
        try:
            path = self.get_document_path(doc_id)

            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)

            data["pill"] = {
                "subtitle": subtitle or "",
                "intro": intro or "",
                "tips": [
                    {
                        "position": i + 1,
                        "headline": t["headline"],
                        "body": t["body"],
                        "links": t["links"] or [],
                    }
                    for i, t in enumerate(tips_data)
                ],
                "closing": closing or "",
                "contactEmail": contact_email or "",
            }

            with open(path, "w", encoding="utf-8") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=2)
        except Exception as exc:
            logger.warning(f"Error reescribiendo archivo de doc {doc_id}: {exc}", exc_info=True)

    def get_document_path(self, document_id: int) -> Path:
        """Devuelve la ruta al archivo generado, validando propiedad y existencia."""
        self.assert_document_ownership(document_id)

        doc = get_document_by_id(document_id)
        if not doc:
            raise ValueError(f"Documento {document_id} no existe")

        if not doc.filename:
            raise ValueError(f"Documento {document_id} no tiene filename")

        cfg = self._read_cfg()
        path = cfg["output_dir"] / doc.filename
        if not path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {doc.filename}")

        return path

    def delete_document(self, document_id: int) -> None:
        """Elimina el documento de BD y el archivo en disco de forma atómica."""

        cfg = self._read_cfg()
        try:
            delete_document_file(document_id, cfg["output_dir"])
        except Exception as exc:
            raise RuntimeError(f"Error eliminando documento: {exc}")

    def list_user_documents(self) -> list[dict]:
        """Lista todos los documentos del usuario, ordenados por fecha descendente."""
        from sqlalchemy import desc
        from src.modules.shared import Document

        session = get_db_session()
        docs = (
            session.query(Document)
            .filter(Document.user_id == self.user.id)
            .filter(Document.document_type == "aegis")
            .order_by(desc(Document.generated_at))
            .limit(100)
            .all()
        )
        fields_map = {
            "id":          "id",
            "title":       "title",
            "subtitle":    "subtitle",
            "filename":    "filename",
            "format":      "format",
            "status":      "status",
            "generated_at": "generatedAt",
            "topic_id":    "topicId",
        }
        return serialize_document_list(docs, fields_map)

    def get_topics(self) -> list[dict]:
        """Devuelve todos los temas disponibles ordenados por título."""
        session = get_db_session()
        repo = AegisDocumentRepository(session=session)

        topics = repo.get_topics()
        return [{"id": t.id, "title": t.title} for t in topics]

    def assert_document_ownership(self, document_id: int) -> AegisDocument:
        """
        Checks whether the document with the given ID is owned by
        the user with the given ID.

        Args:
            document_id: id of the document to check
            user_id: id of the user that potentially can own the document

        Returns:
            True if the user with the given id owns \
            the document with the given ID and false otherwise

        Raises:
            DocumentError if the document was not found
        """
        session = get_db_session()
        doc_repo = AegisDocumentRepository(session=session)
        doc = doc_repo.get_by_id(document_id)
        if not doc:
            raise DocumentError(f"Documento {document_id} no encontrado")
        if doc.user_id != self.user.id: # type: ignore
            raise DocumentError(f"Documento {document_id} no encontrado")

        return doc

    # =========================================================================
    # WORKFLOW DE GENERACIÓN (privado)
    # =========================================================================

    @staticmethod
    def execute_aegis_generation(document_id: int, topic_id: int, tweaks: dict, user_id: int) -> None:
        """Entry point submitted to the TaskQueue for background generation."""
        from src.modules.users.managers import UserManager

        user = UserManager().get_user_by_id(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        AegisManager(user)._run_generation_workflow(document_id, topic_id, tweaks)

    def _run_generation_workflow(
        self,
        document_id: int,
        topic_id:    int,
        tweaks:      dict[str, Any],
    ) -> None:
        """Orquesta todos los pasos de generación en el thread secundario."""
        with job_context():
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
                self._persist_content_atomic(document_id, content, tweaks.get("mentionContact"))
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
                logger.info(f"Documento {document_id} generado: {filename}")

            except Exception as exc:
                logger.error(f"Error en workflow {document_id}: {exc}", exc_info=True)
                self._update_document_status(
                    document_id=document_id,
                    status="error",
                    error=str(exc)[:100],
                )

    def _persist_content_atomic(
        self, document_id: int, content: AegisContent, contact_email_from_tweaks: str | None = None
    ) -> None:
        """Persiste el contenido de la píldora y los tips usando el repositorio."""
        default_email = "seguridad@empresa.com"
        contact_email = (
            contact_email_from_tweaks
            if contact_email_from_tweaks and contact_email_from_tweaks != default_email
            else (content.contact_email or None)
        )

        tips_data = [
            {
                "headline": tip.headline,
                "body": tip.body,
                "links": (
                    [{"text": lk["text"], "url": lk["url"]} for lk in tip.links]
                    if tip.links else None
                ),
            }
            for tip in content.tips
        ]

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            repo.update_content_fields(
                doc_id=document_id,
                subtitle=content.subtitle,
                intro=content.intro,
                closing=content.closing,
                contact_email=contact_email,
                company=content.company,
            )
            repo.save_tips(document_id, tips_data)
            logger.info(f"Contenido persistido para doc {document_id}: {len(content.tips)} tips")

    def _persist_alerts_atomic(self, document_id: int, alerts: list[AegisAlert]) -> None:
        """Persiste alertas usando el repositorio."""
        alerts_data = []
        for alert in alerts:
            pub_date: date | None = None
            if alert.published:
                try:
                    pub_date = date.fromisoformat(alert.published[:10])
                except ValueError:
                    pass

            alerts_data.append({
                "source": alert.source.value,
                "source_label": "INCIBE-CERT" if alert.source == AlertSource.INCIBE else "NVD/CVE",
                "title": alert.title[:256],
                "published": pub_date,
                "severity": alert.severity.value if isinstance(alert.severity, Enum) else alert.severity,
                "affected_brands": alert.brands or None,
                "description": alert.description[:500] if alert.description else None,
                "url": alert.url[:512],
            })

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            repo.save_alerts(document_id, alerts_data)
            logger.info(f"Alertas persistidas para doc {document_id}: {len(alerts)}")

    def _read_cfg(self) -> dict:
        stack_dir = Path(CR.get_directory_of(CR.DirectoryType.STACK_AEGIS))
        output_dir = Path(CR.get_directory_of(CR.DirectoryType.OUTPUT_AEGIS))
        output_dir.mkdir(parents=True, exist_ok=True)

        ollama_host, ollama_model = CR.get_ollama_environment()
        aegis = CR.get_aegis_config() or {}

        return {
            "enabled":          bool(aegis.get("enabled", True)),
            "ollama_host":      ollama_host,
            "ollama_model":     ollama_model,
            "timeout_seconds":  120,
            "stack_dir":        stack_dir,
            "output_dir":       output_dir,
        }

    def _get_topic_from_db(self, topic_id: int | None) -> tuple[Topic | None, bool]:
        """Devuelve (topic, was_random). Si topic_id no existe, elige uno aleatorio."""
        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            if topic_id is not None:
                topic = repo.get_topic_by_id(topic_id)
                if topic:
                    return topic, False
                logger.warning(f"Topic {topic_id} no encontrado, usando aleatorio")

            all_topics = repo.get_topics()
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
                logger.warning(f"No se pudo leer {f}: {exc}", exc_info=True)

        return "\n\n---\n\n".join(contents)

    def _create_pending_document(self, topic_id: int) -> int:
        """Crea un registro AegisDocument en estado 'pending' y devuelve su ID."""
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        placeholder = f"pending_{ts}_{self.user.id}_{topic_id}"

        doc = AegisDocument(
            title=placeholder[:64],
            filename=f"{placeholder}.json"[:128],
            status="pending",
            format="json",
            topic_id=topic_id,
            user_id=self.user.id,
            is_ai_generated=1,
        )

        with UnitOfWork() as uow:
            repo = AegisDocumentRepository(uow)
            saved_doc = repo.save(doc)

        return saved_doc.id # type: ignore

    def _update_document_status(
        self,
        document_id: int,
        status: str,
        title: str | None = None,
        filename: str | None = None,
        error: str | None = None,
    ) -> None:
        """Actualiza el estado del documento usando el repositorio."""
        doc = get_document_by_id(document_id)
        if not doc:
            logger.error(f"Documento {document_id} no encontrado para actualizar estado")
            return

        set_generated_at = status == "done"
        update_document_status(doc, status, title, filename, error, set_generated_at)
