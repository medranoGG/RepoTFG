# TFG- Técnicas de aprendizaje automático para la detección y clasificación de URLs maliciosas

Este repositorio contiene el código fuente y configuraciones necesarias para ejecutar una aplicación que analiza y valida URLs, determinando si son maliciosas o no. A continuación, se detallan los pasos para clonar el repositorio, iniciar el contenedor y ejecutar el script de validación.

### Requisitos Previos 🛒

- [Git](https://git-scm.com/)
- [Docker](https://www.docker.com/)
- [Docker Compose](https://docs.docker.com/compose/)

### Instalación y Uso 💻

#### 1. Clonar el Repositorio

Para obtener una copia local del proyecto, ejecuta el siguiente comando:

```sh
git clone URL_DEL_REPOSITORIO
```

#### 2. Iniciar el Contenedor 

Para ejecutar la aplicación en un entorno Dockerizado, usa el siguiente comando:

```sh
sudo docker-compose up -d
```

#### 3. Ejecutar el Script de Validación

El repositorio incluye un script llamado `send_url.sh`, que permite enviar URLs a la API para su análisis. Antes de ejecutarlo, es necesario otorgarle permisos de ejecución:

```sh
chmod u+x send_url.sh
```

Validar una URL:

```sh
./send_url.sh URL_A_ANALIZAR
```

La API procesará la URL y devolverá los resultados en formato JSON.

#### 4. Interpretar la Respuesta 

La respuesta JSON contiene los siguientes parámetros:

- **input**: La URL proporcionada por el usuario.
- **prediction**: Un porcentaje de legitimidad de la URL.
- **prediction_boolean**: Un valor booleano que devuelve `1` si la URL es legítima y `-1` si es maliciosa.

---

Este README proporciona una guía rápida y clara sobre cómo utilizar el proyecto.

