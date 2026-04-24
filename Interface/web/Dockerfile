FROM nginx:alpine

COPY pages/ /usr/share/nginx/html/
COPY resources/ /usr/share/nginx/html/resources/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]