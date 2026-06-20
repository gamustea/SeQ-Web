"""
Document utilities for AI-generated content.

Pure helpers to manage ``Document`` rows and their on-disk files (status
updates, listing, deletion). The AI generation itself lives in the ``scribe``
module; this file no longer holds any LLM client logic.
"""

import logging

from datetime import datetime
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)

from src.modules.shared import Document
from src.modules.infrastructure import UnitOfWork


# =========================================================================
# DOCUMENT UTILITIES
# =========================================================================
# Funciones puras para gestión de documentos. NO gestionan sesiones.
# Los repositorios usan UnitOfWork para la persistencia.


def update_document_status(
    doc: Document,
    status: str,
    title: str | None = None,
    filename: str | None = None,
    error: str | None = None,
    set_generated_at: bool = False,
) -> Document:
    """
    Actualiza el estado de un documento con campos opcionales.

    Args:
        doc: Instancia del documento a actualizar.
        status: Nuevo estado ('pending', 'running', 'done', 'error').
        title: Nuevo título (truncado a 64 caracteres).
        filename: Nuevo nombre de archivo (truncado a 128).
        error: Mensaje de error para estado 'error' (truncado a 50).
        set_generated_at: Si True, asigna datetime.utcnow() (para estado 'done').

    Returns:
        El documento con los campos actualizados (no hace flush/commit).
    """
    doc.status = status # type: ignore
    if title:
        doc.title = title[:64]
    if filename:
        doc.filename = filename[:128] # type: ignore
    if set_generated_at and status == "done":
        doc.generated_at = datetime.utcnow() # type: ignore
    if error and status == "error":
        doc.title = f"[ERR{doc.id}] {error[:50]}"[:64]

    with UnitOfWork() as uow:
        uow.session.add(doc) # type: ignore
    return doc


def get_document_path(doc: Document, output_dir: Path) -> Path:
    """
    Calcula la ruta absoluta al archivo del documento.

    Args:
        doc: Instancia del documento.
        output_dir: Directorio base de salida.

    Returns:
        Ruta absoluta al archivo.

    Raises:
        ValueError: Si el documento no tiene filename.
    """
    if not doc.filename: # type: ignore
        raise ValueError(f"Documento {doc.id} no tiene filename")
    return output_dir / doc.filename # type: ignore


def serialize_document_list(
    documents: List[Document],
    fields_map: dict[str, str] | None = None,
) -> List[dict]:
    """
    Serializa una lista de documentos a diccionarios.

    Args:
        documents: Lista de instancias de documentos.
        fields_map: Mapeo opcional de campos del modelo a nombres de salida.
                    Si None, usa los campos por defecto: id, title, filename,
                    format, status, generatedAt (como isoformat).

    Returns:
        Lista de diccionarios con los datos serializados.
    """
    default_fields = {
        "id": "id",
        "title": "title",
        "filename": "filename",
        "format": "format",
        "status": "status",
        "generated_at": "generatedAt",
    }
    mapping = fields_map or default_fields

    result = []
    for doc in documents:
        item = {}
        for model_field, output_name in mapping.items():
            value = getattr(doc, model_field, None)
            if value is None:
                item[output_name] = None
            elif isinstance(value, datetime):
                item[output_name] = value.isoformat()
            else:
                item[output_name] = value
        result.append(item)
    return result


def safe_delete_file(filename: str) -> bool:
    """
    Elimina un archivo del sistema de archivos de forma segura.

    Args:
        filename: Ruta al archivo a eliminar.

    Returns:
        True si el archivo fue eliminado o no existía, False si hubo error.
    """
    import os

    if not filename:
        return False

    if not os.path.exists(filename):
        return True

    try:
        os.remove(filename)
        return True
    except Exception as exc:
        logger.warning(f"No se pudo eliminar el archivo {filename}: {exc}", exc_info=True)
        return False


def get_document_by_id(document_id: int) -> Document | None:
    """
    Obtiene un documento por su ID.

    Args:
        document_id: ID del documento a obtener.

    Returns:
        Instancia del documento o None si no existe.
    """
    with UnitOfWork() as uow:
        return uow.session.get(Document, document_id)


def get_documents_by_user(user_id: int, limit: int = 100, document_type: str | None = None) -> List[dict]:
    """
    Obtiene todos los documentos de un usuario ordenados por fecha descendente.

    Args:
        user_id: ID del usuario.
        limit: Número máximo de documentos a devolver (default: 100).
        document_type: Tipo de documento a filtrar ('aegis', 'sentinel', etc.).

    Returns:
        Lista de diccionarios con los datos de los documentos.
    """
    with UnitOfWork() as uow:
        from sqlalchemy import desc
        query = uow.session.query(Document).filter(Document.user_id == user_id)
        if document_type:
            query = query.filter(Document.document_type == document_type)
        docs = (
            query
            .order_by(desc(Document.generated_at))
            .limit(limit)
            .all()
        )
        return serialize_document_list(docs)


def delete_document_file(document_id: int, output_dir: Path) -> None:
    """
    Elimina un documento de la base de datos y su archivo en disco.

    Args:
        document_id: ID del documento a eliminar.
        output_dir: Directorio donde se encuentran los archivos.

    Raises:
        ValueError: Si el documento no existe.
    """
    with UnitOfWork() as uow:
        doc = uow.session.get(Document, document_id)
        if not doc:
            raise ValueError(f"Documento {document_id} no existe")

        if doc.filename: # type: ignore
            file_path = output_dir / doc.filename
            if file_path.exists():
                safe_delete_file(str(file_path))
                logger.info(f"Archivo eliminado: {file_path}")

        uow.session.delete(doc)
        logger.info(f"Documento {document_id} eliminado de BD")
