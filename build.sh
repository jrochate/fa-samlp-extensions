docker build -f Dockerfile.build -t fa-samlp-extensions:build .
docker create --name fa_samlp_ext_tmp fa-samlp-extensions:build
mkdir -p dist
docker cp fa_samlp_ext_tmp:/out/fa-samlp-extensions.jar dist/
docker rm fa_samlp_ext_tmp
ls -lh dist/fa-samlp-extensions.jar
