# Demonstration container with NO outbound network access (Report Sections 9.2, 21).
# Ollama runs on the host; the container reaches it only over the host gateway.
#
#   docker build -t agent-tool-injection .
#   docker run --rm --network none agent-tool-injection            # mock backend
#
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["python", "main.py", "--backend", "mock", "--scenario", "experiments", "--trials", "100"]
