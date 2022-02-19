# Docker Tricks
Docker is completely awesome, and since im quite new to it, i decided i was going to make myself some notes on it so i can remember the commands properly.
## Starting a Ubuntu Container
Starting a container in docker is something pretty simple, for this we just need a single command. In our case since we want to start a Ubuntu container we'll use one of the following commands.
```
For the latest ubuntu version
$ sudo docker run -it ubuntu 

For a specific ubuntu version add a colomn with the version number
$ sudo docker run -it ubuntu:18.04
```
## Restore an accidentally exited a container
It sometimes happens that you quit a container without actually wanting to, you can restore the container with 2 really simple commands.
```
$ sudo docker start $(sudo docker ps -q -l)
$ sudo docker attach $(sudo docker ps -q -l)
```
