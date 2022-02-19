# Working with socket.io
**Websockets** is a technology that provides real time communication between a client and a server via a TCP connection, eliminating the need for customers to continuously check wether API endpoints have updates or new content. Clients create a single connection a WebSocket server, and wait to listen to new server events or messages.

The main advantage of WebSockets is that they are more efficient because they reduce the network load and send information in the form of messages to a large number of clients.

Among the main features of WebSockets, we can highlight the following :
- They provide bidirectional (full duplex) communication over a single TCP connection
- They provide real-time communication between a server and its connecting clients. This enables the emergency of new applications oriented toward managing events asynchronously.
- They provide concurrency and improve performance, optimizing response times and resulting in more reliable web applications.

## Implementing a server with socket.io
To implement our server based on socket.io, we need to introduce other modules like **asyncio** and **aiohttp**.
- **asyncio** is a Python module that helps us to do the concurrent programming of a single thread in Python. It's available in Python 3.7 - the documentation is available [here](https://docs.python.org/3/library/asyncio.html). 
- **aiohttp** is a library for building server and client application built in **asyncio**. The module uses the advantages of WebSockets natively to communicate between different parts of the application synchronously. The documentation is available [here](http://aiohttp.readthedocs.io/en/stable)
