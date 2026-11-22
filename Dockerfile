FROM node:22-alpine
WORKDIR /damda
COPY app ./app
COPY server ./server
ENV DATA_DIR=/data PORT=8787
VOLUME /data
EXPOSE 8787
USER node
CMD ["node", "server/server.js"]
