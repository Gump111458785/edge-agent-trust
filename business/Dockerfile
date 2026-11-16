FROM python:3.11-slim
WORKDIR /opt/edge-agent-trust
COPY business/requirements.txt business/requirements.txt
RUN pip install --no-cache-dir -r business/requirements.txt
COPY business/app business/app
COPY business/migrations business/migrations
USER 10001:10001
CMD ["uvicorn", "business.app.main:create_business_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
