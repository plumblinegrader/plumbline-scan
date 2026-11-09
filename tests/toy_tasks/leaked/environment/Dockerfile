FROM python:3.12-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends git >/dev/null && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY shapes.py /app/shapes.py
COPY fixed_shapes.py /tmp/fixed_shapes.py
RUN git init -q -b main && git -c user.email=a@b -c user.name=toy add shapes.py \
 && git -c user.email=a@b -c user.name=toy commit -qm base \
 && git checkout -q -b fix && cp /tmp/fixed_shapes.py shapes.py \
 && git -c user.email=a@b -c user.name=toy commit -qam "fix area" \
 && git checkout -q main && rm /tmp/fixed_shapes.py
