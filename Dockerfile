FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create the flag (fixed name at build time)
RUN echo "CTF{pyth0n_grpc_f1l3_wr1t3}" > /flag.txt

# Make entrypoint executable
RUN chmod +x entrypoint.sh

EXPOSE 1337 50045

ENTRYPOINT ["./entrypoint.sh"]
