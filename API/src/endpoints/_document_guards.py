
"""
Utilidades compartidas para verificación de documentos.
Agnóstico al tipo de documento (AegisDocument / SentinelDocument),
opera directamente sobre el modelo base Document.
"""

from src.core.model import Document


def fetch_document_for_user(session, doc_id: int, user_id: int) -> Document:
    """
    Recupera un Document de BD verificando que pertenece al usuario.

    Raises:
        ValueError:     Si no existe o el user_id no coincide.
    """
    doc = session.get(Document, doc_id)
    if not doc or doc.user_id != user_id:
        raise ValueError(f"Documento {doc_id} no encontrado")
    return doc


def assert_document_ready(doc: Document) -> None:
    """
    Verifica que el documento esté en estado 'done'.

    Raises:
        PermissionError:  Si el estado no es 'done'.
    """
    if doc.status != "done":
        raise PermissionError(f"Documento no listo. Estado: {doc.status}")