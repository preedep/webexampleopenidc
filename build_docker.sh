docker rmi $(docker images -f "dangling=true" -q) --force
export DOCKER_BUILDKIT=1
docker build --tag webexample3:1.0 . --platform linux/amd64


