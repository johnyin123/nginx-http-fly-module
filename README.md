# nginx-http-fly-module

## config
upstream a-backend {
    zone  fly  128k;
   192.168.1.101:81;
   192.168.1.101:82;
   192.168.1.101:83;
}

upstream b-backend {
    zone  fly  128k;
   192.168.1.102:81;
   192.168.1.102:82;
   192.168.1.102:83;
}

server {

  location /fly {
      fly  on;
  }

  location /assets {
      alias  html/fly;
  }

}

##install
> ./configure --add-module={src}/nginx-http-fly-module && make
> cp -R {src}/html/fly > {dst}/html

