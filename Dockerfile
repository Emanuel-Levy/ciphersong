FROM python:3.12-slim

WORKDIR /app

# Instala apenas as dependências enxutas do Backend FastAPI + PyMongo
RUN pip install --no-cache-dir \
    fastapi>=0.115.0 \
    uvicorn>=0.30.0 \
    "pymongo[srv]>=4.8.0" \
    python-dotenv>=1.0.0 \
    pydantic>=2.8.0

COPY ciphersong/__init__.py ./ciphersong/__init__.py
COPY ciphersong/database ./ciphersong/database
COPY backend_api.py ./backend_api.py

EXPOSE 8000

CMD ["uvicorn", "backend_api:app", "--host", "0.0.0.0", "--port", "8000"]
