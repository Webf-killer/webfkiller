FROM python:3.8
WORKDIR /app
COPY . /app
RUN pip install flask
CMD ["python", "attackweb.py"]

