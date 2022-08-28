docker build -t openssl_build .
docker run -dit --name temp_build openssl_build
docker cp temp_build:/opt/openssl-static/ ./build
docker stop temp_build
docker rm -f temp_build