import urllib.parse
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, scoped_session, sessionmaker

from src.misc.configread import ConfigReader
from src.misc.logging import SecOpsLogger

_ENGINE = None
_SESSION_FACTORY = None


def initialize_engine(database_url: Optional[str] = None):
    """
    Inicializa el engine y el session factory una sola vez.
    Debe ser llamado al inicio de la aplicación.
    """
    global _ENGINE, _SESSION_FACTORY

    if _ENGINE is None:
        if database_url is None:
            (USERNAME, PASSWORD, HOST, DBNAME) = ConfigReader().get_db_crendetials()
            database_url = (
                f"postgresql+psycopg2://{USERNAME}:{urllib.parse.quote(PASSWORD)}@{HOST}:{15432}/{DBNAME}"
            )

        _ENGINE = create_engine(
            database_url,
            pool_pre_ping=True,
            pool_recycle=3600,
            echo=False,
            isolation_level="READ COMMITTED"
        )

        _SESSION_FACTORY = scoped_session(
            sessionmaker(
                bind=_ENGINE,
                expire_on_commit=False,
                autoflush=True,
                autocommit=False
            )
        )


class BaseManager:
    """
    Clase base para todos los managers que necesitan acceso a la BD.
    Proporciona gestión de sesiones thread-safe y métodos de utilidad.
    """

    def __init__(self, session: Optional[Session] = None):
        global _SESSION_FACTORY

        if _SESSION_FACTORY is None:
            initialize_engine()

        if session is not None:
            self.session = session
            self._owns_session = False
        else:
            self.session = _SESSION_FACTORY()  # type: ignore
            self._owns_session = True

        self.logger = SecOpsLogger(self.__class__.__name__).get_logger()

    def _check_session(self):
        if self.session is None:
            raise Exception("La sesión de base de datos no está establecida.")

    def close_session(self):
        if self._owns_session and self.session is not None:
            try:
                self.session.close()
                _SESSION_FACTORY.remove()  # type: ignore
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
                    global _SESSION_FACTORY
                    if _SESSION_FACTORY is not None:
                        self.session = _SESSION_FACTORY()
                        self.logger.info("Sesión recreada después de error en rollback")
            except Exception as recreate_err:
                self.logger.error(f"No se pudo recrear la sesión: {recreate_err}")

    @staticmethod
    def close_all_sessions():
        global _SESSION_FACTORY
        if _SESSION_FACTORY is not None:
            _SESSION_FACTORY.remove()
