# Neat & Clean Laundry Admin

[Open the admin dashboard](./Tidal%20Admin.html)

## Run locally

Requires Node.js 22.13 or newer. From this folder, start the server:

```sh
npm start
```

Then open:

- [Customer website](http://127.0.0.1:3000/nac.html)
- [Admin dashboard](http://127.0.0.1:3000/Tidal%20Admin.html)

On a new database, the admin page opens a first-admin setup form. Create the administrator there; setup is accepted only from this computer. Later visits show the staff sign-in form.

## Accounts and bookings

Customer sign-ups are saved to SQLite. Passwords are salted and hashed with scrypt; plaintext passwords are never stored. Signed-in customer sessions use HTTP-only cookies.

Bookings are validated and saved by the server. The admin dashboard lists customers and orders, refreshes every five seconds, and supports order-status updates and test bookings.

## Data and security

The database is stored at `data/neat-clean.sqlite` and is excluded from source control. Back it up regularly. The server binds to `127.0.0.1` by default. Do not expose it directly to the internet; a public deployment needs HTTPS, production-grade hosting, and additional access controls.