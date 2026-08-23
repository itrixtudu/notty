export function listenHttpServer(server, listenArgs) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      server.off('error', onError);
      server.off('listening', onListening);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onListening = () => {
      cleanup();
      resolve(server);
    };

    server.once('error', onError);
    server.once('listening', onListening);
    try {
      server.listen(...listenArgs);
    } catch (error) {
      onError(error);
    }
  });
}
