import time
import urllib.parse
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, scoped_session, sessionmaker


ENGINE = None
SESSION_FACTORY = None


def initialize_engine(database_url: Optional[str] = None):
    """
    Inicializa el engine y el session factory una sola vez.
    Debe ser llamado al inicio de la aplicación.
    """
    global ENGINE, SESSION_FACTORY

    if ENGINE is None:
        from src.modules.misc import ConfigReader
        t0 = time.perf_counter()
        if database_url is None:
            db_creds = ConfigReader.get_db_credentials()
            database_url = (
                f"{db_creds['dialect']}://{db_creds['username']}:{urllib.parse.quote(db_creds['password'])}@{db_creds['host']}:{db_creds['port']}/{db_creds['dbname']}"
            )

        ENGINE = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=False,
            isolation_level="READ COMMITTED"
        )

        SESSION_FACTORY = scoped_session(
            sessionmaker(
                bind=ENGINE,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False
            )
        )

    return ENGINE

def warmup_connection(engine=None) -> None:
    """Abre y cierra una conexión real para precalentar el pool."""
    global SESSION_FACTORY
    if SESSION_FACTORY is None:
        initialize_engine()
    from sqlalchemy import text
    session = SESSION_FACTORY()
    session.execute(text("SELECT 1"))
    session.close()
    SESSION_FACTORY.remove()

class BaseManager:
    """
    Clase base para todos los managers que necesitan acceso a la BD.
    Proporciona gestión de sesiones thread-safe y métodos de utilidad.
    """

    def __init__(self, session: Optional[Session] = None):
        global SESSION_FACTORY

        if SESSION_FACTORY is None:
            initialize_engine()

        if session is not None:
            self.session = session
            self._owns_session = False
        else:
            self.session = SESSION_FACTORY()
            self._owns_session = True

        from src.modules.misc import SecOpsLogger
        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()

    def _check_session(self):
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")

    def close_session(self):
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
                SESSION_FACTORY.remove()
            except Exception as e:
                self.logger.warning(f"Error al cerrar sesión: {e}")

    def _safe_commit(self):
        try:
            self.session.commit()
            return True
        except SQLAlchemyError as err:
            self.logger.error(f"Error durante commit: {err}")
            self._safe_rollback()
            raise

    def _safe_rollback(self):
        try:
            if self.session is not None:
                self.session.rollback()
                self.logger.debug("Rollback ejecutado exitosamente")
        except Exception as e:
            self.logger.warning(f"Error durante rollback: {e}")
            try:
                if self._owns_session:
                    self.session.close()
                    global SESSION_FACTORY
                    if SESSION_FACTORY is not None:
                        self.session = SESSION_FACTORY()
                        self.logger.info("Sesión recreada después de error en rollback")
            except Exception as recreate_err:
                self.logger.error(f"No se pudo recrear la sesión: {recreate_err}")

    @staticmethod
    def close_all_sessions():
        global SESSION_FACTORY
        if SESSION_FACTORY is not None:
            SESSION_FACTORY.remove()

    # pylint: disable=unused-argument
    def _get_by_field(self, model, field, value, lock_for_update=False):
        from sqlalchemy import and_
        query = self.session.query(model)
        if lock_for_update:
            query = query.with_for_update()
        return query.filter(and_(getattr(model, field) == value)).first()

    def _get_children(self, model, foreign_key, parent_id):
        return self.session.query(model).filter(getattr(model, foreign_key) == parent_id).all()

    def _save(self, obj):
        self.session.add(obj)
        self._safe_commit()
        self.session.refresh(obj)
        return obj

    def _update(self, obj):
        self.session.flush()
        self._safe_commit()
        return obj

    def _delete(self, obj):
        self.session.delete(obj)
        self._safe_commit()
