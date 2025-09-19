# syntax=docker/dockerfile:1.6
FROM python:3.11.9-slim@sha256:8fb099199b9f2d70342674bd9dbccd3ed03a258f26bbd1d556822c6dfc60c317 AS builder
ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv "$VIRTUAL_ENV"
ENV PATH="$VIRTUAL_ENV/bin:$PATH" \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.lock pyproject.toml README.md LICENSE /app/
COPY src /app/src
RUN pip install --upgrade pip && \
    pip install --require-hashes -r requirements.lock && \
    pip install --no-deps .

FROM gcr.io/distroless/python3-debian12:nonroot@sha256:d0f0f30dca9d4b574e7915ff6eb13d93c71bc4aa3f53dea66d54f2eabe813514
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
COPY --from=builder /opt/venv /opt/venv
WORKDIR /workspace
ENTRYPOINT ["rtx"]
CMD ["scan"]
