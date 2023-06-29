FROM python:3.9-slim

COPY requirements.txt /gaction/requirements.txt

RUN cd /gaction && \
    pip install -r requirements.txt && \
    rm -rf /var/cache/apt/* /var/lib/apt/lists/*

COPY . /gaction

ENTRYPOINT ["/gaction/entrypoint.sh"]