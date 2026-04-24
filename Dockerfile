# JWBreaker Dockerfile
# builds a lightweight container for running JWBreaker
# without needing a local Python environment

FROM python:3.11-slim

# set working directory
WORKDIR /app

# copy requirements first so Docker can cache the pip install layer
# separately from the source code - means rebuilds are faster
COPY requirements.txt .

# install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# copy the rest of the project
COPY . .

# create the output directory for reports
RUN mkdir -p /app/output

# default entrypoint - runs jwbreaker.py with any arguments passed in
ENTRYPOINT ["python", "jwbreaker.py"]

# show help if no arguments are provided
CMD ["--help"]