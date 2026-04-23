FROM nginx:alpine

COPY pages/ /usr/share/nginx/html/pages/
COPY resources/ /usr/share/nginx/html/resources/

COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]