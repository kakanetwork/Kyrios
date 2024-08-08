
# Configuração Nginx (Servidor Web Público)
        sudo adduser --system --group --no-create-home nginx
        sudo apt-get install -y nginx 
        sudo mkdir -p /srv/nginx
        sudo chown -R root:nginx /srv/nginx
        sudo chmod -R 750 /srv/nginx

        sudo ln -s /etc/nginx/sites-available/kyrios.conf /etc/nginx/sites-enabled

        sudo nginx -t
        sudo systemctl reload nginx

        sudo usermod -aG django www-data
        sudo usermod -aG nginx www-data


![alt text](/static/img/nginx.png)