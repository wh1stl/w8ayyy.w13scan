FROM golang:1.18.3-alpine3.15 as build-stage
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk update && apk add --no-cache git ca-certificates && update-ca-certificates && apk add --no-cache tzdata
RUN go env -w GO111MODULE=on && go env -w GOPROXY=https://goproxy.io,direct
RUN cd / && git clone https://github.com/Qianlitp/crawlergo
RUN cd /crawlergo && go mod download
RUN cd /crawlergo/cmd/crawlergo && go build -o crawlergo crawlergo_cmd.go

FROM python:3.10.5-alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
RUN apk update && apk --no-cache add git build-base libffi-dev libxml2-dev libxslt-dev libressl-dev gcc chromium
# RUN cd / && git clone https://github.com/w-digital-scanner/w13scan
RUN mkdir -p w13scan/
COPY requirements.txt /w13scan/requirements.txt
RUN pip install -r /w13scan/requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
COPY --from=build-stage /crawlergo/cmd/crawlergo/crawlergo /usr/bin
RUN chmod 777 /usr/bin/crawlergo
ADD W13SCAN /w13scan/W13SCAN
WORKDIR /w13scan/W13SCAN
ENTRYPOINT ["/bin/ash"]