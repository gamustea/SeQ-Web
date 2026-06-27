# Plan de mejoras funcionales para el detector de phishing

## Objetivo

Este documento define las capacidades que debería incorporar el detector de phishing para mejorar su precisión frente a campañas evidentes, avanzadas y altamente sutiles. El foco está en **qué debe detectar, correlacionar, priorizar y revisar** el sistema, sin entrar en detalles de implementación.

## Prioridades generales

El detector debería evolucionar desde un análisis centrado en cabeceras hacia una evaluación multicapa que combine autenticación, identidad del remitente, enlaces, contenido, contexto del mensaje y consistencia global.

Las decisiones no deberían apoyarse en una sola señal aislada. El sistema debería ser capaz de distinguir entre:

- Correos legítimos con lenguaje de seguridad o facturación.
- Phishing técnico que falla en autenticación o alineación.
- Phishing sofisticado que aparenta ser legítimo en las cabeceras, pero falla en dominios, enlaces, contexto o coherencia.

## Capacidades que debería incorporar

### 1. Evaluación completa de autenticación

El sistema debería analizar de forma conjunta:

- SPF.
- DKIM.
- DMARC.
- Alineación entre dominios autenticados y dominio visible en `From`.
- Coherencia entre `From`, `Return-Path`, `Reply-To` y `Message-ID`.

No basta con detectar que SPF o DKIM hacen `pass`. El sistema debería comprobar si el dominio que supera la autenticación es realmente coherente con la identidad visible del remitente.

### 2. Verificación de alineación DMARC real

El detector debería identificar expresamente casos en los que:

- SPF pasa, pero con un dominio distinto del `From`.
- DKIM pasa, pero firma un dominio no alineado con el `From`.
- El resultado global de DMARC es `fail` aunque existan señales parciales positivas.

También debería tratar como sospechosos los correos donde la identidad visible parezca confiable, pero la alineación entre dominios no sea correcta.

### 3. Análisis de dominios del remitente

El sistema debería revisar si el dominio del remitente:

- Es el dominio oficial esperado de la marca o entidad.
- Es un dominio parecido o lookalike.
- Usa palabras engañosas como `security`, `alerts`, `verify`, `support`, `billing`, `account`, `login`, `secure`, etc.
- Añade subdominios largos para aparentar legitimidad.
- Es un dominio recién visto, poco habitual o no relacionado con la entidad suplantada.

También debería poder detectar el uso de marcas conocidas dentro de dominios no oficiales, por ejemplo cuando el nombre de la marca aparece incrustado en un dominio ajeno.

### 4. Análisis del dominio real de los enlaces

El detector debería extraer y evaluar todos los enlaces del mensaje, no solo si existen, sino:

- El dominio registrable real del enlace.
- La coherencia entre el dominio del enlace y la marca del remitente.
- El uso de subdominios engañosos que aparenten pertenecer a una marca conocida.
- La diferencia entre el texto visible del enlace y su destino real.
- La presencia de redirecciones, parámetros sospechosos o rutas de login sensibles.

Debería tratar como señal de alto riesgo cualquier correo que aparente provenir de una marca concreta pero dirija a un dominio externo no esperado.

### 5. Listas blancas funcionales por marca o proveedor

El programa debería contemplar un conjunto de dominios esperados para proveedores conocidos, especialmente en servicios que suelen ser objetivo de phishing, como:

- GitHub.
- AWS.
- Microsoft.
- Google.
- PayPal.
- Bancos.
- Plataformas universitarias.
- Herramientas corporativas o internas del entorno de trabajo.

La validación no debería limitarse al dominio del remitente. También debería revisar si los enlaces y recursos principales del mensaje pertenecen al conjunto esperado de dominios oficiales.

### 6. Detección de dominios lookalike y brand impersonation

El detector debería marcar como sospechosos mensajes que utilicen:

- Dominios visualmente parecidos a marcas reales.
- Marcas incluidas como subdominio de un dominio ajeno.
- Variaciones con guiones, palabras adicionales o sufijos engañosos.
- Combinaciones que parezcan “técnicas” o “corporativas” pero no pertenezcan al dominio legítimo.

Esta capacidad es crítica para detectar phishing que pasa SPF para su propio dominio pero suplanta visualmente a una marca legítima.

### 7. Revisión de cabeceras auxiliares y coherencia global

El sistema debería inspeccionar con más profundidad:

- `Reply-To`.
- `Return-Path`.
- `Message-ID`.
- `In-Reply-To`.
- `References`.
- Cadena de `Received`.
- Resultados `Authentication-Results` y `ARC` cuando existan.

No debería limitarse a leer esos campos por separado. También debería valorar si son coherentes entre sí y con la historia que aparenta el mensaje.

### 8. Detección de secuestro de hilos aparentes

El detector debería ser capaz de analizar correos que simulan ser respuestas a conversaciones previas legítimas. Para ello, debería revisar:

- Si el asunto reutiliza un hilo previo para generar confianza.
- Si `In-Reply-To` y `References` parecen consistentes o artificiales.
- Si el contenido del cuerpo realmente encaja con el hilo que aparenta continuar.
- Si el mensaje mezcla una apariencia de continuidad con una petición anómala de acción inmediata.

Los correos en hilo son especialmente peligrosos porque reducen la sospecha del usuario incluso cuando hay señales débiles de fraude.

### 9. Análisis semántico contextual del contenido

El motor debería evaluar el contenido del mensaje teniendo en cuenta:

- Solicitudes de credenciales.
- Solicitudes de códigos MFA, tokens, recuperación de sesión o rotación de claves.
- Peticiones de datos financieros, documentación personal o datos de pago.
- Peticiones de acceso a portales, SSO, cambio de contraseña o verificación urgente.
- Referencias a suspensión, bloqueo, revisión de seguridad, incidencias o pagos.

La clave no es solo detectar palabras sospechosas, sino **el propósito operativo del mensaje**: qué acción intenta provocar y qué nivel de riesgo tiene esa acción.

### 10. Reducción de dependencia de palabras clave aisladas

El detector no debería castigar en exceso palabras como:

- `security`
- `invoice`
- `urgent`
- `account`
- `password`
- `billing`
- `review`

Muchos correos legítimos usan exactamente ese lenguaje. El sistema debería valorar esas palabras en combinación con autenticación, dominio, destino del enlace, tipo de acción solicitada y coherencia del mensaje.

### 11. Evaluación del tipo de acción solicitada

El sistema debería distinguir entre acciones de bajo riesgo y acciones de alto riesgo.

Ejemplos de acciones de alto riesgo:

- Introducir credenciales.
- Rotar tokens desde un enlace embebido.
- Verificar identidad.
- Descargar un archivo ejecutable o documento sensible.
- Autorizar acceso.
- Cambiar contraseña.
- Completar un pago.
- Subir documentos personales.

Aunque el mensaje parezca técnicamente correcto, una acción muy sensible debería elevar la severidad si el enlace o el dominio no son plenamente confiables.

### 12. Correlación entre remitente, marca y destino

El detector debería preguntarse en cada mensaje:

- ¿Quién dice ser?
- ¿Quién lo envía realmente?
- ¿A dónde quiere llevar al usuario?
- ¿Qué acción quiere que haga?
- ¿Es normal que esa marca use ese dominio, ese tono y ese flujo?

La correlación entre identidad aparente y destino real debería convertirse en una capacidad central del sistema.

### 13. Reputación y frecuencia de dominios

El programa debería contemplar como señal útil:

- Si el dominio ya ha aparecido antes en correos legítimos.
- Si el dominio es habitual para esa marca.
- Si el dominio es completamente nuevo dentro del entorno analizado.
- Si el mensaje introduce infraestructuras no vistas antes para una marca que normalmente usa pocos dominios estables.

No es necesario que un dominio sea malicioso para ser sospechoso: basta con que sea inesperado para esa identidad.

### 14. Detección de enlaces que aparentan ser internos u oficiales

El sistema debería marcar como sospechosos enlaces que:

- Simulan ser paneles internos, SSO, consola de seguridad o recuperación de cuenta.
- Usan rutas como `/login`, `/auth`, `/verify`, `/security`, `/billing`, `/password`, `/token`, `/review`, `/session`, `/unlock`.
- Intentan parecer parte de una consola conocida, pero en dominios no oficiales.

Este tipo de rutas no son una prueba suficiente por sí mismas, pero combinadas con un dominio anómalo son una señal muy fuerte.

### 15. Clasificación por severidad y no solo por etiqueta binaria

El sistema debería poder devolver niveles diferenciados, por ejemplo:

- Legítimo.
- Bajo riesgo.
- Sospechoso.
- Phishing probable.
- Phishing confirmado.

Esto permitiría reflejar mejor casos muy sutiles donde no existe una prueba única concluyente, pero sí una combinación de indicios relevantes.

### 16. Explicabilidad orientada a revisión

El programa debería indicar de forma clara qué grupos de señales han influido en el veredicto, como por ejemplo:

- Autenticación correcta o incorrecta.
- Alineación de dominios correcta o incorrecta.
- Enlaces coherentes o incoherentes con la marca.
- Petición de acción sensible.
- Uso de dominio lookalike.
- Anomalías en cabeceras auxiliares.
- Apariencia de secuestro de hilo.

No se trata de explicar el algoritmo, sino de dejar claro qué debe revisar quien audita el resultado.

## Casos que el programa debería cubrir explícitamente

El detector debería estar preparado para identificar, como categorías diferenciadas, los siguientes escenarios:

- Phishing obvio con faltas, IPs literales y dominios no confiables.
- Phishing corporativo que simula soporte interno, SSO o incidencias técnicas.
- Suplantación de marcas con SPF correcto para un dominio atacante pero DMARC no alineado.
- Correos técnicamente limpios cuyo principal indicador malicioso es el dominio real del enlace.
- Correos en apariencia legítimos que intentan secuestrar hilos o conversaciones previas.
- Notificaciones reales de seguridad, facturación y accesos, para evitar falsos positivos.

## Criterios de calidad esperados

Las mejoras del programa deberían perseguir estos objetivos funcionales:

- Reducir falsos negativos en phishing avanzado y sutil.
- Reducir falsos positivos en correos legítimos de seguridad, facturación y actividad de cuentas.
- Priorizar señales estructurales fuertes frente a palabras clave aisladas.
- Detectar dominios y enlaces engañosos aunque la autenticación parcial parezca correcta.
- Valorar el mensaje como una unidad completa y no como un conjunto de reglas independientes.

## Resultado esperado tras aplicar estas mejoras

Un detector maduro debería ser capaz de distinguir no solo si un correo “parece raro”, sino si existe una discrepancia material entre la identidad que presenta, la infraestructura desde la que se envía, el destino al que lleva y la acción que intenta provocar.

Ese cambio de enfoque es el paso necesario para pasar de detectar phishing básico a detectar phishing convincente y de alto nivel.
