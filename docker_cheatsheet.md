# Get image

  docker pull name/name

# Start container

  docker run -d -p 33334:80 --platform linux/amd64  name/name

# List running containers

  docker container ls

# Get container shell

  docker exec -it container_name /bin/bash 

# Stop container

  docker stop "CONTAINER ID"
