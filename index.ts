import { Database } from "bun:sqlite";
import * as jose from "jose";

const db = new Database("mydb.sqlite", { create: true });

db.run(
  "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT, password TEXT)"
);

interface User {
  id: number;
  name: string;
  email: string;
  password: string;
}

const notfounfResponse = new Response("Not found!", { status: 404 });
const unauthorizedResponse = new Response("Unauthorized", { status: 401 });

const server = Bun.serve({
  port: 3000,
  async fetch(req: Request) {
    const url = new URL(req.url);

    if (url.pathname === "/users") {
      if (req.method === "POST") {
        const body: any = await req.json();
        const passwordHash = await Bun.password.hash(body.password, "bcrypt");
        db.run(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          body.name,
          body.email,
          passwordHash
        );

        return new Response(null, { status: 201 });
      } else if (req.method === "GET") {
        const users: User[] = db
          .query("SELECT id, name, email, password FROM users")
          .all() as User[];

        return new Response(JSON.stringify({ users }), {
          headers: { "Content-Type": "application/json" },
        });
      }
    } else if (url.pathname.match(/^\/users\/(\d+)$/)) {
      const id = Number(url.pathname.split("/").pop());

      const userDb = db
        .query("SELECT id, name, email FROM users WHERE id = ?")
        .get(id) as User;

      if (!userDb) return notfounfResponse;

      if (req.method === "GET") {
        return Response.json({
          user: userDb,
        });
      } else if (req.method === "DELETE") {
        db.run("DELETE FROM users WHERE id = ?", [id]);
        return new Response();
      } else if (req.method === "PUT") {
        const body: any = await req.json();
        db.run(
          "UPDATE users set name = ?, email = ? WHERE id = ?",
          body.name,
          body.email,
          id
        );
        return new Response();
      }
    } else if (url.pathname === "/auth/login" && req.method === "POST") {
      const body: any = await req.json();
      const userDb = db
        .query("SELECT * FROM users WHERE email = ?")
        .get(body.email) as User;

      if (!userDb) return unauthorizedResponse;

      const truePassword = await Bun.password.verify(
        body.password,
        userDb.password
      );
      if (!truePassword) return unauthorizedResponse;

      const secret = new TextEncoder().encode(Bun.env.JWT_SECRET);
      const token = await new jose.SignJWT({
        userId: userDb.id,
      })
        .setProtectedHeader({ alg: "HS256" })
        .setExpirationTime('2h')
        .sign(secret);

      return Response.json({
        token,
      });
    }

    return notfounfResponse;
  },
});

console.log(`Listening on http://localhost:${server.port} ...`);
