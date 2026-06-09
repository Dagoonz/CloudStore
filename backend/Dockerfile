FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . .

# Expose port 5000 for gunicorn
EXPOSE 5000

# Use shell form to allow $PORT variable expansion
CMD gunicorn --bind 0.0.0.0:$PORT --workers 3 app:app
