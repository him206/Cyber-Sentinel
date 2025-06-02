# Use an official Python base image
FROM python:3.10-slim

# Set the working directory
WORKDIR /app

# Copy requirements and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your app code
COPY . .

# Expose the port (change if needed)
EXPOSE 5000

# Command to run your Flask app
CMD ["python", "app.py"]
