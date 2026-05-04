# Contributing to NullBot

¡Gracias por querer contribuir! NullBot es un proyecto comunitario y tu aporte importa.

## Formas de contribuir

### 1. Reportar falsos positivos (MUY IMPORTANTE)
Si NullBot detecta un archivo legítimo como amenaza, ábrelo como issue con:
- Hash SHA-256 del archivo
- Nombre del fabricante / software
- Regla YARA o firma que lo detectó

Los falsos positivos dañan la reputación del proyecto — los priorizamos.

### 2. Agregar reglas YARA
1. Crea un archivo en `signatures/rules/nombre_familia.yar`
2. Sigue el formato de `botnet_agents.yar`
3. Incluye `meta:` con descripción, severidad, categoría y autor
4. Prueba contra EICAR y muestras reales (en entorno aislado)
5. Abre un PR con descripción de la familia detectada

### 3. Mejoras al motor C++
- Rama: `feature/tu-feature`
- Sigue el estilo existente (namespaces, headers separados)
- Incluye tests unitarios en `tests/unit/`
- Corre `cmake --build build && ctest` antes de hacer PR

### 4. Módulo de red / anti-botnet
El área más importante. Se necesita ayuda con:
- Mejoras al detector de beaconing
- Modelo de ML para DGA (n-gram mejorado)
- Integración con WFP (Windows Filtering Platform)

## Proceso de PR

1. Fork → branch → commits descriptivos
2. `git commit -m "feat(scanner): add entropy threshold config"`
3. PR contra `develop`, no `main`
4. Un maintainer revisará en 72 horas

## Configuración de entorno

Ver `README.md` — requisitos: VS 2022, CMake 3.25+, Python 3.11+

## Código de conducta

Somos una comunidad técnica y respetuosa. Zero tolerancia a ataques personales.

## ⚠️ Uso ético

NullBot es software defensivo. Cualquier uso ofensivo o para atacar sistemas
ajenos viola la licencia GPL-3.0 y posiblemente leyes locales e internacionales.
