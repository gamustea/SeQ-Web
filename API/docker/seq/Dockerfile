# ──────────────────────────────────────────────────────────────────────────────
# Dockerfile  —  SeQ API (Flask + Nmap + Nikto)
#
# Etapas:
#   builder  → instala dependencias Python en un venv aislado
#   runtime  → imagen final mínima con solo lo necesario
# ──────────────────────────────────────────────────────────────────────────────

# ── Etapa 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Dependencias de compilación (para paquetes con extensiones C)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY API/requirements.txt .

RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt


# ── Etapa 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

LABEL maintainer="SecOps Team"
LABEL description="SeQ API — Flask + Nmap + Nikto (Linux nativo)"

# Herramientas de red instaladas de forma nativa (sin WSL)
#   nmap   → escaneo de puertos
#   perl   → requerido por nikto
#   libpq5 → cliente PostgreSQL (runtime de psycopg2)
#   git    → necesario para clonar nikto (no está en los repos de Debian Trixie)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    perl \
    libpq5 \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Nikto no está en los repositorios de Debian Trixie → se instala desde GitHub
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# Copiar el venv construido en la etapa anterior
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app

# Copiar el código de la API
COPY API/ ./
# Directorios que necesita la app en tiempo de ejecución
RUN mkdir -p temp logs data/aegis/output data/aegis/stack

# Usuario no-root para mayor seguridad
# (nmap necesita cap NET_RAW/NET_ADMIN que se conceden en docker-compose, no aquí)
RUN groupadd -r secops && useradd -r -g secops secops && \
    chown -R secops:secops /app
USER secops

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:5000/say-hello || exit 1

CMD ["python", "run.py"]
