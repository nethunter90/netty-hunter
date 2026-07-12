import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;

/**
 * Deliberately vulnerable Java deserialization fixture — no build tooling
 * needed beyond the JDK itself (com.sun.net.httpserver.HttpServer is
 * built-in). Deserializes the raw, attacker-controlled POST body via
 * ObjectInputStream.readObject() — the exact bug class
 * deserialization-prober.ts's Java path detects via ysoserial's URLDNS
 * gadget (which fires its OOB side effect during readObject() itself,
 * using only core java.util/java.net classes always on any JVM's
 * classpath — no vulnerable library needed).
 *
 * Run: javac Fixture.java && java Fixture [port]
 */
public class Fixture {
    public static void main(String[] args) throws IOException {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 5002;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new DeserializeHandler());
        server.setExecutor(null);
        server.start();
        System.out.println("java-deser-fixture listening on " + port);
    }

    static class DeserializeHandler implements HttpHandler {
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                exchange.sendResponseHeaders(405, -1);
                exchange.close();
                return;
            }
            byte[] body = exchange.getRequestBody().readAllBytes();
            byte[] respBytes;
            try {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body));
                Object obj = ois.readObject();
                respBytes = ("deserialized: " + obj).getBytes();
            } catch (Exception e) {
                respBytes = ("error: " + e.toString()).getBytes();
            }
            exchange.sendResponseHeaders(200, respBytes.length);
            exchange.getResponseBody().write(respBytes);
            exchange.close();
        }
    }
}
