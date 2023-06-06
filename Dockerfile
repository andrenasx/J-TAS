FROM python:3.9-slim-bullseye

COPY requirements.txt /gaction/requirements.txt

RUN cd /gaction && \
    pip install -r requirements.txt && \
    rm -rf /var/lib/apt/lists/*

COPY . /gaction

ENTRYPOINT ["/gaction/entrypoint.sh"]