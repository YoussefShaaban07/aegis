# Aegis public demo on Hugging Face Spaces (Docker Space). The Space only needs this file and README.md:
# it downloads Aegis from GitHub and runs the simulated plant, the guard and the dashboard on port 7860.
# To pick up new commits from GitHub: Space Settings -> "Factory rebuild".
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 user
USER user
WORKDIR /home/user
RUN git clone --depth 1 https://github.com/YoussefShaaban07/aegis.git app
WORKDIR /home/user/app
RUN pip install --no-cache-dir --user -r requirements.txt
ENV PATH=/home/user/.local/bin:$PATH \
    AEGIS_DEMO=1 AEGIS_PUBLIC=1 AEGIS_HTTPS=1 AEGIS_HOST=0.0.0.0 PORT=7860 PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["python", "-m", "aegis.server"]
